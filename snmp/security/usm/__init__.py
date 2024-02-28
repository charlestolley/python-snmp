__all__ = [
    "InvalidEngineID", "InvalidSecurityLevel", "InvalidUserName",
    "AuthProtocol", "PrivProtocol", "UserBasedSecurityModule",
]

import threading
from time import time

from snmp.asn1 import *
from snmp.ber import *
from snmp.exception import IncomingMessageError
from snmp.message.v3 import *
from snmp.security import *
from snmp.security.levels import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

class AuthProtocol:
    def __init__(self, key: bytes) -> None:
        raise NotImplementedError()

    @classmethod
    def computeKey(cls, secret: bytes) -> bytes:
        raise NotImplementedError()

    @classmethod
    def localizeKey(cls, key: bytes, engineID: bytes) -> bytes:
        raise NotImplementedError()

    @classmethod
    def localize(cls, secret: bytes, engineID: bytes) -> bytes:
        return cls.localizeKey(cls.computeKey(secret), engineID)

    @property
    def msgAuthenticationParameters(self) -> bytes:
        raise NotImplementedError()

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError()

class PrivProtocol:
    def __init__(self, key: bytes) -> None:
        raise NotImplementedError()

    def decrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
        salt: bytes,
    ) -> bytes:
        raise NotImplementedError()

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        raise NotImplementedError()

from .credentials import *
from .parameters import *
from .timekeeper import *
from .users import *

class UnsupportedSecLevel(IncomingMessageError):
    pass

class NotInTimeWindow(IncomingMessageError):
    pass

class UnknownUserName(IncomingMessageError):
    pass

class UnknownEngineID(IncomingMessageError):
    pass

class WrongDigest(IncomingMessageError):
    pass

class DecryptionError(IncomingMessageError):
    pass

class InvalidEngineID(ValueError):
    pass

class InvalidSecurityLevel(ValueError):
    pass

class DiscoveredEngine:
    def __init__(self) -> None:
        self.namespace: Optional[str] = None
        self.refCount = 0

    def assign(self, namespace: str) -> Tuple[bool, bool]:
        assigned = True
        initialized = True

        if namespace != self.namespace:
            if self.refCount:
                assigned = False
            else:
                self.namespace = namespace
                initialized = False

        if assigned:
            self.refCount += 1

        return assigned, initialized

    def release(self, namespace: str) -> bool:
        assert self.namespace == namespace
        assert self.refCount > 0

        self.refCount -= 1
        return self.refCount == 0

class UserTable:
    def __init__(self) -> None:
        self.engines: Dict[bytes, Dict[bytes, LocalizedCredentials]] = {}

    def assignCredentials(self,
        engineID: bytes,
        userName: bytes,
        credentials: LocalizedCredentials,
    ) -> None:
        try:
            users = self.engines[engineID]
        except KeyError:
            users = dict()
            self.engines[engineID] = users

        users[userName] = credentials

    def getCredentials(self,
        engineID: bytes,
        userName: bytes,
    ) -> LocalizedCredentials:
        try:
            users = self.engines[engineID]
        except KeyError as err:
            raise InvalidEngineID(engineID) from err

        try:
            return users[userName]
        except KeyError as err:
            raise InvalidUserName(userName) from err

class UserBasedSecurityModule(SecurityModule[SNMPv3Message]):
    MODEL = SecurityModel.USM

    def __init__(self) -> None:
        self.engines: Dict[bytes, DiscoveredEngine] = {}
        self.lock = threading.Lock()
        self.namespaces: Dict[str, NamespaceConfig] = {}
        self.timekeeper = TimeKeeper()
        self.users = UserTable()

    def addUser(self,
        userName: str,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        privSecret: Optional[bytes] = None,
        secret: bytes = b"",
        default: bool = False,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
        namespace: str = "",
    ) -> None:
        credentials = Credentials(
            authProtocol,
            authSecret,
            privProtocol,
            privSecret,
            secret,
        )

        with self.lock:
            try:
                config = self.namespaces[namespace]
            except KeyError:
                config = NamespaceConfig()
                self.namespaces[namespace] = config

            config.addUser(
                userName,
                credentials,
                defaultSecurityLevel,
                default,
            )

    def getDefaultSecurityLevel(self,
        userName: str,
        namespace: str = "",
    ) -> SecurityLevel:
        config = self.getNamespace(namespace)
        return config.findUser(userName).defaultSecurityLevel

    def getDefaultUser(self, namespace: str = "") -> str:
        return self.getNamespace(namespace).defaultUserName

    def getNamespace(self, namespace: str = "") -> NamespaceConfig:
        try:
            return self.namespaces[namespace]
        except KeyError as err:
            errmsg = "No users defined"

            if namespace:
                errmsg += f" in namespace \"{namespace}\""

            raise ValueError(errmsg) from err

    def registerRemoteEngine(self,
        engineID: bytes,
        namespace: str = "",
    ) -> bool:
        with self.lock:
            try:
                engine = self.engines[engineID]
            except KeyError:
                engine = DiscoveredEngine()
                self.engines[engineID] = engine

            assigned, initialized = engine.assign(namespace)

            # Read as "assigned but not initialized"
            if not initialized and assigned:
                config = self.namespaces[namespace]
                for userName, userConfig in config:
                    self.users.assignCredentials(
                        engineID,
                        userName.encode(),
                        userConfig.credentials.localize(engineID),
                    )

            return assigned

    def unregisterRemoteEngine(self,
        engineID: bytes,
        namespace: str = "",
    ) -> None:
        with self.lock:
            try:
                engine = self.engines[engineID]
            except KeyError:
                assert False, f"Engine {engineID!r} was never registered"
            else:
                if engine.release(namespace):
                    del self.engines[engineID]

    def prepareOutgoing(self,
        message: SNMPv3Message,
        engineID: bytes,
        securityName: bytes,
        timestamp: Optional[float] = None,
    ) -> bytes:
        if timestamp is None:
            timestamp = time()

        if message.header.flags.authFlag:
            with self.lock:
                user = self.users.getCredentials(engineID, securityName)

            if not user.auth:
                userName = securityName.decode
                errmsg = f"Authentication is disabled for user \"{userName}\""
                raise InvalidSecurityLevel(errmsg)

            snmpEngineBoots, snmpEngineTime = self.timekeeper.getEngineTime(
                engineID,
                timestamp=timestamp,
            )

            msgAuthenticationParameters = user.auth.msgAuthenticationParameters
            msgPrivacyParameters = b''

            if message.header.flags.privFlag:
                if not user.priv:
                    userName = securityName.decode
                    errmsg = f"Privacy is disabled for user \"{userName}\""
                    raise InvalidSecurityLevel(errmsg)

                ciphertext, msgPrivacyParameters = user.priv.encrypt(
                    cast(ScopedPDU, message.scopedPDU).encode(),
                    snmpEngineBoots,
                    snmpEngineTime,
                )

                message.encryptedPDU = OctetString(ciphertext)

        else:
            snmpEngineBoots = 0
            snmpEngineTime = 0
            msgAuthenticationParameters = b''
            msgPrivacyParameters = b''

        securityParameters = UsmSecurityParameters(
            engineID,
            snmpEngineBoots,
            snmpEngineTime,
            securityName,
            msgAuthenticationParameters,
            msgPrivacyParameters,
        )

        message.securityParameters = OctetString(securityParameters.encode())
        wholeMsg = message.encode()

        if message.header.flags.authFlag:
            location = UsmSecurityParameters.findSignature(
                SNMPv3Message.findSecurityParameters(wholeMsg)
            )

            signature = cast(AuthProtocol, user.auth).sign(wholeMsg)
            wholeMsg = location.replace(signature)

        return wholeMsg

    def processIncoming(self,
        message: SNMPv3Message,
        timestamp: Optional[float] = None,
    ) -> None:
        if timestamp is None:
            timestamp = time()

        securityParameters = UsmSecurityParameters.decode(
            message.securityParameters.original,
        )

        message.securityEngineID = securityParameters.engineID
        message.securityName     = securityParameters.userName
        remoteIsAuthoritative = True

        if not message.header.flags.authFlag:
            if remoteIsAuthoritative:
                self.timekeeper.hint(
                    securityParameters.engineID,
                    securityParameters.engineBoots,
                    securityParameters.engineTime,
                    timestamp=timestamp
                )

            return

        try:
            with self.lock:
                user = self.users.getCredentials(
                    securityParameters.engineID,
                    securityParameters.userName,
                )
        except InvalidEngineID as err:
            raise UnknownEngineID(securityParameters.engineID) from err
        except InvalidUserName as err:
            raise UnknownUserName(securityParameters.userName) from err

        if user.auth is None:
            username = securityParameters.userName.decode()
            errmsg = f"Authentication is disabled for user \"{username}\""
            raise UnsupportedSecLevel(errmsg)
        elif message.header.flags.privFlag and user.priv is None:
            username = securityParameters.userName.decode()
            errmsg = f"Data privacy is disabled for user \"{username}\""
            raise UnsupportedSecLevel(errmsg)

        padding = user.auth.msgAuthenticationParameters
        if len(securityParameters.signature) != len(padding):
            raise WrongDigest("Invalid signature length")

        assert securityParameters.wholeMsg is not None
        wholeMsg = bytearray(securityParameters.wholeMsg)

        assert securityParameters.signatureIndex is not None
        start = securityParameters.signatureIndex
        stop = start + len(padding)
        wholeMsg[start:stop] = padding

        if user.auth.sign(wholeMsg) != securityParameters.signature:
            raise WrongDigest("Invalid signature")

        try:
            if not self.timekeeper.updateAndVerify(
                securityParameters.engineID,
                securityParameters.engineBoots,
                securityParameters.engineTime,
                timestamp,
            ):
                raise NotInTimeWindow((
                    securityParameters.engineID,
                    securityParameters.engineBoots,
                    securityParameters.engineTime,
                ))
        except InvalidEngineID as err:
            raise UnknownEngineID(securityParameters.engineID) from err

        if message.header.flags.privFlag:
            try:
                message.plaintext = cast(PrivProtocol, user.priv).decrypt(
                    cast(OctetString, message.encryptedPDU).data,
                    securityParameters.engineBoots,
                    securityParameters.engineTime,
                    securityParameters.salt,
                )
            except ValueError as err:
                raise DecryptionError(str(err)) from err
