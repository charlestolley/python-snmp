__all__ = ["InvalidSecurityLevel", "UserBasedSecurityModule"]

import threading
from time import time

from snmp.exception import *
from snmp.message.v3 import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.models import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

from . import AuthProtocol, DecryptionError, PrivProtocol
from .parameters import *
from .timekeeper import *
from .users import *

class UnsupportedSecLevel(IncomingMessageError):
    pass

class UnknownUserName(IncomingMessageError):
    pass

class UnknownEngineID(IncomingMessageError):
    pass

class WrongDigest(IncomingMessageError):
    pass

class InvalidSecurityLevel(ValueError):
    pass

class UserBasedSecurityModule(SecurityModule[SNMPv3Message]):
    MODEL = SecurityModel.USM

    def __init__(self) -> None:
        self.timeLock = threading.Lock()
        self.userLock = threading.Lock()

        self.timekeeper = TimeKeeper()
        self.users = UserRegistry()

    def addUser(self,
        userName: str,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        privSecret: Optional[bytes] = None,
        secret: Optional[bytes] = None,
        default: Optional[bool] = None,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
        namespace: str = "",
    ) -> None:
        with self.userLock:
            self.users.addUser(
                userName.encode(),
                namespace,
                default=default,
                authProtocol=authProtocol,
                privProtocol=privProtocol,
                authSecret=authSecret,
                privSecret=privSecret,
                secret=secret,
                defaultSecurityLevel=defaultSecurityLevel,
            )

    def getDefaultSecurityLevel(self,
        userName: str,
        namespace: str = "",
    ) -> SecurityLevel:
        with self.userLock:
            return self.users.getDefaultSecurityLevel(
                userName.encode(),
                namespace,
            )

    def getDefaultUser(self, namespace: str = "") -> Optional[str]:
        with self.userLock:
            user = self.users.getDefaultUser(namespace)

        return user.decode() if user is not None else None

    def registerRemoteEngine(self,
        engineID: bytes,
        namespace: str = "",
    ) -> bool:
        with self.userLock:
            return self.users.assign(engineID, namespace)

    def unregisterRemoteEngine(self,
        engineID: bytes,
        namespace: str = "",
    ) -> None:
        with self.userLock:
            _ = self.users.release(engineID, namespace)

    def prepareOutgoing(self,
        message: SNMPv3Message,
        engineID: bytes,
        securityName: bytes,
        timestamp: Optional[float] = None,
    ) -> bytes:
        if timestamp is None:
            timestamp = time()

        if message.header.flags.authFlag:
            with self.userLock:
                user = self.users.getCredentials(engineID, securityName)

            if user.auth is None:
                userName = securityName.decode()
                errmsg = f"Authentication is disabled for user \"{userName}\""
                raise InvalidSecurityLevel(errmsg)

            with self.timeLock:
                engineTime = self.timekeeper.getEngineTime(engineID, timestamp)

            snmpEngineBoots, snmpEngineTime = engineTime
            msgAuthenticationParameters = user.auth.msgAuthenticationParameters
            msgPrivacyParameters = b''

            if message.header.flags.privFlag:
                if user.priv is None:
                    userName = securityName.decode()
                    errmsg = f"Privacy is disabled for user \"{userName}\""
                    raise InvalidSecurityLevel(errmsg)

                assert message.scopedPDU is not None
                ciphertext, msgPrivacyParameters = user.priv.encrypt(
                    message.scopedPDU.encode(),
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

            assert user.auth is not None
            signature = user.auth.sign(wholeMsg)
            wholeMsg = location.replace(signature)

        return wholeMsg

    def processIncoming(self,
        message: SNMPv3Message,
        timestamp: Optional[float] = None,
    ) -> None:
        if timestamp is None:
            timestamp = time()

        securityParameters = UsmSecurityParameters.decodeExact(
            message.securityParameters.original,
        )

        message.securityEngineID = securityParameters.engineID
        message.securityName     = securityParameters.userName
        remoteIsAuthoritative = True

        if not message.header.flags.authFlag:
            if remoteIsAuthoritative:
                with self.timeLock:
                    self.timekeeper.hint(
                        securityParameters.engineID,
                        timestamp,
                        securityParameters.engineBoots,
                        securityParameters.engineTime,
                    )

            return

        try:
            with self.userLock:
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

        assert securityParameters.signatureIndex is not None
        start = securityParameters.signatureIndex
        stop = start + len(padding)

        assert securityParameters.wholeMsg is not None
        signature = subbytes(securityParameters.wholeMsg, start, stop)
        wholeMsg = signature.replace(padding)

        if user.auth.sign(wholeMsg) != securityParameters.signature:
            raise WrongDigest("Invalid signature")

        try:
            with self.timeLock:
                self.timekeeper.updateAndVerify(
                    securityParameters.engineID,
                    timestamp,
                    securityParameters.engineBoots,
                    securityParameters.engineTime,
                )
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
