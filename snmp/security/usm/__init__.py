__all__ = [
    "InvalidEngineID", "InvalidUserName", "InvalidSecurityLevel",
    "AuthProtocol", "PrivProtocol",
    "UsmSecurityParameters", "UserBasedSecurityModule",
]

from abc import abstractmethod
import threading

from time import time
from snmp.ber import *
from snmp.exception import IncomingMessageError
from snmp.message.v3 import *
from snmp.security import *
from snmp.security.levels import *
from snmp.types import *
from snmp.typing import *
from snmp.utils import *

class AuthProtocol:
    @abstractmethod
    def __init__(self, key: bytes) -> None:
        ...

    @classmethod
    @abstractmethod
    def computeKey(cls, secret: bytes) -> bytes:
        ...

    @classmethod
    @abstractmethod
    def localizeKey(cls, key: bytes, engineID: bytes) -> bytes:
        ...

    @classmethod
    def localize(cls, secret: bytes, engineID: bytes) -> bytes:
        return cls.localizeKey(cls.computeKey(secret), engineID)

    @property
    @abstractmethod
    def msgAuthenticationParameters(self) -> bytes:
        ...

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        ...

class PrivProtocol:
    @abstractmethod
    def __init__(self, key: bytes) -> None:
        ...

    @abstractmethod
    def decrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
        salt: bytes,
    ) -> bytes:
        ...

    @abstractmethod
    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        ...

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

class InvalidUserName(ValueError):
    pass

class InvalidSecurityLevel(ValueError):
    pass

class TimeEntry:
    def __init__(self,
        engineBoots: int,
        latestBootTime: Optional[float] = None,
        authenticated: bool = False,
    ) -> None:
        if latestBootTime is None:
            latestBootTime = time()

        self.authenticated = authenticated
        self.snmpEngineBoots = engineBoots
        self.latestBootTime = latestBootTime
        self.latestReceivedEngineTime = 0

    def snmpEngineTime(self, timestamp: float) -> int:
        return int(timestamp - self.latestBootTime)

class TimeKeeper:
    MAX_ENGINE_BOOTS: ClassVar[int] = (1 << 31) - 1
    TIME_WINDOW_SIZE: ClassVar[int] = 150

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.table: Dict[bytes, TimeEntry] = {}

    def getEngineTime(self,
        engineID: bytes,
        timestamp: Optional[float] = None,
    ) -> Tuple[int, int]:
        if timestamp is None:
            timestamp = time()

        with self.lock:
            try:
                entry = self.table[engineID]
            except KeyError:
                return 0, 0

            return entry.snmpEngineBoots, entry.snmpEngineTime(timestamp)

    def update(self,
        engineID: bytes,
        msgBoots: int = 0,
        msgTime: int = 0,
        timestamp: Optional[float] = None,
    ) -> None:
        self.updateAndVerify(engineID, msgBoots, msgTime, False, timestamp)

    def updateAndVerify(self,
        engineID: bytes,
        msgBoots: int,
        msgTime: int,
        auth: bool = True,
        timestamp: Optional[float] = None,
    ) -> bool:
        if timestamp is None:
            timestamp = time()

        with self.lock:
            try:
                entry = self.table[engineID]
            except KeyError as err:
                entry = TimeEntry(msgBoots, timestamp - msgTime, auth)
                self.table[engineID] = entry

            withinTimeWindow = False
            if not entry.authenticated:
                entry.snmpEngineBoots = msgBoots
                entry.latestBootTime = timestamp - msgTime
                entry.latestReceivedEngineTime = msgTime
                withinTimeWindow = True
            elif auth:
                if msgBoots > entry.snmpEngineBoots:
                    entry.snmpEngineBoots = msgBoots
                    entry.latestBootTime = timestamp
                    entry.latestReceivedEngineTime = 0

                if msgBoots == entry.snmpEngineBoots:
                    if msgTime > entry.latestReceivedEngineTime:
                        calculatedBootTime = timestamp - msgTime
                        if calculatedBootTime < entry.latestBootTime:
                            entry.latestBootTime = calculatedBootTime

                        entry.latestReceivedEngineTime = msgTime
                        withinTimeWindow = True
                    else:
                        snmpEngineTime = entry.snmpEngineTime(timestamp)
                        difference = snmpEngineTime - msgTime
                        if difference <= self.TIME_WINDOW_SIZE:
                            withinTimeWindow = True

                if entry.snmpEngineBoots == self.MAX_ENGINE_BOOTS:
                    withinTimeWindow = False

            if auth:
                entry.authenticated = True

            return withinTimeWindow

class Credentials:
    def __init__(self,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[PrivProtocol] = None,
        privSecret: Optional[bytes] = None,
        secret: bytes = b"",
    ) -> None:
        self.authProtocol = None
        self.authKey = None
        self.privProtocol = None
        self.privKey = None

        if authProtocol is None:
            self.maxSecurityLevel = noAuthNoPriv
        else:
            if privProtocol is None:
                self.maxSecurityLevel = authNoPriv
            else:
                self.maxSecurityLevel = authPriv
                self.privProtocol = privProtocol
                self.privKey = authProtocol.computeKey(privSecret or secret)

            self.authProtocol = authProtocol
            self.authKey = authProtocol.computeKey(authSecret or secret)

class LocalizedCredentials:
    def __init__(self,
        auth: Optional[AuthProtocol] = None,
        priv: Optional[PrivProtocol] = None,
    ) -> None:
        self.auth = auth
        self.priv = priv

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

class UserEntry:
    def __init__(self,
        defaultSecurityLevel: SecurityLevel,
        credentials: Credentials
    ) -> None:
        self.credentials = credentials
        self.defaultSecurityLevel = defaultSecurityLevel

class NameSpace:
    def __init__(self, defaultUserName: str):
        self.defaultUserName = defaultUserName
        self.users: Dict[str, UserEntry] = {}

    def __iter__(self) -> Iterator[Tuple[str, UserEntry]]:
        return self.users.items().__iter__()

    def __contains__(self, key: str) -> bool:
        return self.users.__contains__(key)

    def __getitem__(self, key: str) -> UserEntry:
        return self.users.__getitem__(key)

    def __setitem__(self, key: str, item: UserEntry) -> None:
        return self.users.__setitem__(key, item)

class UsmSecurityParameters(Sequence):
    def __init__(self,
        engineID: bytes,
        engineBoots: int,
        engineTime: int,
        userName: bytes,
        authenticationParameters: bytes,
        privacyParameters: bytes,
    ):
        self.engineID = engineID
        self.engineBoots = engineBoots
        self.engineTime = engineTime
        self.userName = userName
        self.authenticationParameters = authenticationParameters
        self.privacyParameters = privacyParameters

    def __iter__(self) -> Iterator[Asn1Encodable]:
        yield OctetString(self.engineID)
        yield Integer(self.engineBoots)
        yield Integer(self.engineTime)
        yield OctetString(self.userName)
        yield OctetString(self.authenticationParameters)
        yield OctetString(self.privacyParameters)

    def __len__(self) -> int:
        return 6

    def __repr__(self) -> str:
        args = (
            str(self.engineID),
            str(self.engineBoots),
            str(self.engineTime),
            str(self.userName),
            str(self.authenticationParameters),
            str(self.privacyParameters),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Authoritative Engine ID: {self.engineID!r}",
            f"{subindent}Authoritative Engine Boots: {self.engineBoots}",
            f"{subindent}Authoritative Engine Time: {self.engineTime}",
            f"{subindent}User Name: {self.userName}",
            f"{subindent}Signature: {self.authenticationParameters}",
            f"{subindent}Encryption Salt: {self.privacyParameters}",
        ))

    @classmethod
    def decode(cls, data, leftovers=False, copy=False, **kwargs):
        return super().decode(data, leftovers, copy, **kwargs)

    @classmethod
    def deserialize(cls, data: Asn1Data):
        engineID, ptr = OctetString.decode(data, leftovers=True)
        engineBoots, ptr  = Integer.decode(ptr, leftovers=True)
        engineTime,  ptr  = Integer.decode(ptr, leftovers=True)
        userName, ptr = OctetString.decode(ptr, leftovers=True)

        authenticationParameters, ptr = OctetString.decode(ptr, leftovers=True)
        privacyParameters = OctetString.decode(ptr)

        return cls(
            cast(bytes, engineID.data),
            engineBoots.value,
            engineTime.value,
            cast(bytes, userName.data),
            cast(bytes, authenticationParameters.data),
            cast(bytes, privacyParameters.data),
        )

class UserBasedSecurityModule(SecurityModule):
    MODEL = SecurityModel.USM

    def __init__(self, engineID: Optional[bytes] = None) -> None:
        self.engineID = engineID
        self.engines: Dict[bytes, DiscoveredEngine] = {}
        self.lock = threading.Lock()
        self.namespaces: Dict[str, NameSpace] = {}
        self.timekeeper = TimeKeeper()
        self.users = UserTable()

        if self.engineID is not None:
            self.timekeeper.update(self.engineID)

    @staticmethod
    def localizeCredentials(
        engineID: bytes,
        credentials: Optional[Credentials] = None,
    ) -> LocalizedCredentials:
        if credentials is None:
           credentials = Credentials()

        auth = None
        priv = None

        if credentials.authProtocol is not None:
            assert credentials.authKey is not None
            auth = credentials.authProtocol(
                credentials.authProtocol.localizeKey(
                    credentials.authKey,
                    engineID,
                )
            )

            if credentials.privProtocol is not None:
                assert credentials.privKey is not None
                priv = credentials.privProtocol(
                    credentials.authProtocol.localizeKey(
                        credentials.privKey,
                        engineID,
                    )
                )

        return LocalizedCredentials(auth, priv)

    def addUser(self,
        userName: str,
        authProtocol: Optional[AuthProtocol] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[PrivProtocol] = None,
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

        if defaultSecurityLevel is None:
            defaultSecurityLevel = credentials.maxSecurityLevel
        elif defaultSecurityLevel > credentials.maxSecurityLevel:
            errmsg = "Unable to support {} without the \"{}\" argument"

            if credentials.maxSecurityLevel.auth:
                param = "privProtocol"
            else:
                param = "authProtocol"

            raise ValueError(errmsg.format(defaultSecurityLevel, param))

        with self.lock:
            try:
                space = self.namespaces[namespace]
            except KeyError:
                space = NameSpace(userName)
                self.namespaces[namespace] = space
            else:
                if userName in space:
                    errmsg = f"User \"{userName}\" is already defined"

                    if namespace:
                        errmsg += f" in namespace \"{namespace}\""

                    raise ValueError(errmsg)

                if default:
                    space.defaultUserName = userName

            space[userName] = UserEntry(defaultSecurityLevel, credentials)

    def getDefaultSecurityLevel(self,
        userName: str,
        namespace: str = "",
    ) -> SecurityLevel:
        space = self.getNameSpace(namespace)

        try:
            user = space[userName]
        except KeyError as err:
            errmsg = f"No user \"{userName}\""

            if namespace:
                errmsg += f" in namespace \"{namespace}\""

            raise ValueError(errmsg) from err

        return user.defaultSecurityLevel

    def getDefaultUser(self, namespace: str = "") -> str:
        return self.getNameSpace(namespace).defaultUserName

    def getNameSpace(self, namespace: str = "") -> NameSpace:
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
                ns = self.namespaces[namespace]
                for userName, entry in ns:
                    self.users.assignCredentials(
                        engineID,
                        userName.encode(),
                        self.localizeCredentials(engineID, entry.credentials)
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
                    message.scopedPDU.encode(),
                    snmpEngineBoots,
                    snmpEngineTime,
                )

                message.encryptedPDU = OctetString(ciphertext)

        else:
            if engineID == self.engineID:
                engineTimeParameters = self.timekeeper.getEngineTime(
                    engineID,
                    timestamp=timestamp,
                )

                snmpEngineBoots, snmpEngineTime = engineTimeParameters
            else:
                snmpEngineBoots = 0
                snmpEngineTime = 0

            msgAuthenticationParameters = b''
            msgPrivacyParameters = b''

        securityParameters = encode(
            SEQUENCE,
            b''.join((
                OctetString(engineID).encode(),
                Integer(snmpEngineBoots).encode(),
                Integer(snmpEngineTime).encode(),
                OctetString(securityName).encode(),
                OctetString(msgAuthenticationParameters).encode(),
                OctetString(msgPrivacyParameters).encode(),
            ))
        )

        message.securityParameters = OctetString(securityParameters)
        wholeMsg = message.encode()

        if message.header.flags.authFlag:
            signature = cast(AuthProtocol, user.auth).sign(wholeMsg)
            securityParameters = encode(
                SEQUENCE,
                b''.join((
                    OctetString(engineID).encode(),
                    Integer(snmpEngineBoots).encode(),
                    Integer(snmpEngineTime).encode(),
                    OctetString(securityName).encode(),
                    OctetString(signature).encode(),
                    OctetString(msgPrivacyParameters).encode(),
                ))
            )

            message.securityParameters = OctetString(securityParameters)
            wholeMsg = message.encode()

        return wholeMsg

    def processIncoming(self,
        message: SNMPv3Message,
        timestamp: Optional[float] = None,
    ) -> None:
        if timestamp is None:
            timestamp = time()

        ptr = decode(
            message.securityParameters.data,
            expected=SEQUENCE,
            leftovers=False,
            copy=False,
        )

        msgAuthoritativeEngineID, ptr = OctetString.decode(ptr, leftovers=True)
        msgAuthoritativeEngineBoots, ptr  = Integer.decode(ptr, leftovers=True)
        msgAuthoritativeEngineTime,  ptr  = Integer.decode(ptr, leftovers=True)
        msgUserName,              ptr = OctetString.decode(ptr, leftovers=True)

        msgAuthenticationParameters, ptr = \
            OctetString.decode(ptr, leftovers=True)
        msgAuthenticationParametersIndex = \
            ptr.start - len(msgAuthenticationParameters.data)
        msgPrivacyParameters = OctetString.decode(ptr)

        engineID = cast(bytes, msgAuthoritativeEngineID.data)
        userName = cast(bytes, msgUserName.data)

        message.securityEngineID = engineID
        message.securityName     = userName

        remoteIsAuthoritative = (engineID != self.engineID)

        if not message.header.flags.authFlag:
            if remoteIsAuthoritative:
                self.timekeeper.update(
                    engineID,
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                    timestamp=timestamp
                )

            return

        try:
            with self.lock:
                user = self.users.getCredentials(engineID, userName)
        except InvalidEngineID as err:
            raise UnknownEngineID(engineID) from err
        except InvalidUserName as err:
            raise UnknownUserName(userName) from err

        if user.auth is None:
            username = userName.decode()
            errmsg = f"Authentication is disabled for user \"{username}\""
            raise UnsupportedSecLevel(errmsg)
        elif message.header.flags.privFlag and user.priv is None:
            username = userName.decode()
            errmsg = f"Data privacy is disabled for user \"{username}\""
            raise UnsupportedSecLevel(errmsg)

        padding = user.auth.msgAuthenticationParameters
        if len(msgAuthenticationParameters.data) != len(padding):
            raise WrongDigest("Invalid signature length")

        wholeMsg = bytearray(message.securityParameters.data.data)

        start = msgAuthenticationParametersIndex
        stop = start + len(padding)
        wholeMsg[start:stop] = padding

        if user.auth.sign(wholeMsg) != msgAuthenticationParameters.data:
            raise WrongDigest("Invalid signature")

        try:
            if not self.timekeeper.updateAndVerify(
                engineID,
                msgAuthoritativeEngineBoots.value,
                msgAuthoritativeEngineTime.value,
                timestamp=timestamp,
            ):
                raise NotInTimeWindow((
                    engineID,
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                ))
        except InvalidEngineID as err:
            raise UnknownEngineID(engineID) from err

        if message.header.flags.privFlag:
            try:
                message.plaintext = cast(PrivProtocol, user.priv).decrypt(
                    cast(bytes, message.encryptedPDU.data),
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                    cast(bytes, msgPrivacyParameters.data),
                )
            except ValueError as err:
                raise DecryptionError(str(err)) from err
