__all__ = [
    "InvalidEngineID", "InvalidUserName", "InvalidSecurityLevel",
    "AuthProtocol", "PrivProtocol", "UserBasedSecurityModule",
]

from abc import abstractmethod
import threading

from time import time
from snmp.ber import decode, encode
from snmp.exception import IncomingMessageError
from snmp.types import *
from snmp.security import *
from snmp.security.levels import *
from snmp.typing import *
from snmp.utils import *

class AuthProtocol:
    @abstractmethod
    def __init__(self, key: bytes) -> None:
        ...

    @classmethod
    @abstractmethod
    def localize(cls, secret: bytes, engineID: bytes) -> bytes:
        ...

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
            if auth or not entry.authenticated:
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
        self.engines: Dict[bytes, Dict[bytes, Credentials]] = {}

    def assignCredentials(self,
        engineID: bytes,
        userName: bytes,
        credentials: Credentials,
    ) -> None:
        try:
            users = self.engines[engineID]
        except KeyError:
            users = dict()
            self.engines[engineID] = users

        users[userName] = credentials

    def getCredentials(self, engineID: bytes, userName: bytes) -> Credentials:
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
        credentials: Mapping[str, Any],
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
    def localize(
        engineID: bytes,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        privSecret: Optional[bytes] = None,
    ) -> Credentials:
        auth = None
        priv = None

        if authProtocol is not None:
            assert authSecret is not None
            authKey = authProtocol.localize(authSecret, engineID)
            auth = authProtocol(authKey)

            if privProtocol is not None:
                assert privSecret is not None
                privKey = authProtocol.localize(privSecret, engineID)
                priv = privProtocol(privKey)

        return Credentials(auth, priv)

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
        credentials: Dict[str, Any] = dict()
        if authProtocol is None:
            maxSecurityLevel = noAuthNoPriv
        else:
            if privProtocol is None:
                maxSecurityLevel = authNoPriv
            else:
                maxSecurityLevel = authPriv
                credentials["privProtocol"] = privProtocol
                credentials["privSecret"] = privSecret or secret

            credentials["authProtocol"] = authProtocol
            credentials["authSecret"] = authSecret or secret

        if defaultSecurityLevel is None:
            defaultSecurityLevel = maxSecurityLevel
        elif defaultSecurityLevel > maxSecurityLevel:
            errmsg = "Unable to support {} without the \"{}\" argument"
            param = "privProtocol" if maxSecurityLevel.auth else "authProtocol"
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
                        self.localize(engineID, **entry.credentials),
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
        header: bytes,
        data: bytes,
        engineID: bytes,
        securityName: bytes,
        securityLevel: SecurityLevel,
    ) -> bytes:
        if securityLevel.auth:
            with self.lock:
                user = self.users.getCredentials(engineID, securityName)

            if not user.auth:
                userName = securityName.decode
                errmsg = f"Authentication is disabled for user \"{userName}\""
                raise InvalidSecurityLevel(errmsg)

            engineTimeParameters = self.timekeeper.getEngineTime(engineID)
            snmpEngineBoots, snmpEngineTime = engineTimeParameters
            msgAuthenticationParameters = user.auth.msgAuthenticationParameters
            msgPrivacyParameters = b''

            if securityLevel.priv:
                if not user.priv:
                    userName = securityName.decode
                    errmsg = f"Privacy is disabled for user \"{userName}\""
                    raise InvalidSecurityLevel(errmsg)

                ciphertext, msgPrivacyParameters = user.priv.encrypt(
                    data,
                    snmpEngineBoots,
                    snmpEngineTime,
                )

                data = OctetString(ciphertext).encode()

        else:
            if engineID == self.engineID:
                engineTimeParameters = self.timekeeper.getEngineTime(engineID)
                snmpEngineBoots, snmpEngineTime = engineTimeParameters
            else:
                snmpEngineBoots = 0
                snmpEngineTime = 0

            msgAuthenticationParameters = b''
            msgPrivacyParameters = b''

        encodedPrivacyParams = OctetString(msgPrivacyParameters).encode()
        securityParameters = encode(
            SEQUENCE,
            b''.join((
                OctetString(engineID).encode(),
                Integer(snmpEngineBoots).encode(),
                Integer(snmpEngineTime).encode(),
                OctetString(securityName).encode(),
                OctetString(msgAuthenticationParameters).encode(),
                encodedPrivacyParams,
            ))
        )

        msgSecurityParameters = OctetString(securityParameters).encode()
        body = b''.join((header, msgSecurityParameters, data))
        wholeMsg = encode(SEQUENCE, body)

        if securityLevel.auth:
            signature = cast(AuthProtocol, user.auth).sign(wholeMsg)
            endIndex = len(wholeMsg) - len(data) - len(encodedPrivacyParams)
            startIndex = endIndex - len(signature)
            wholeMsg = b''.join((
                wholeMsg[:startIndex],
                signature,
                wholeMsg[endIndex:]
            ))

        return wholeMsg

    def processIncoming(self,
        msg: subbytes,
        securityLevel: SecurityLevel,
        timestamp: Optional[float] = None,
    ) -> Tuple[SecurityParameters, bytes]:
        if timestamp is None:
            timestamp = time()

        msgSecurityParameters, msgData = \
            OctetString.decode(msg, leftovers=True, copy=False)

        ptr = decode(
            msgSecurityParameters.data,
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
        securityParameters = SecurityParameters(engineID, userName)

        remoteIsAuthoritative = (engineID != self.engineID)

        if not securityLevel.auth:
            if remoteIsAuthoritative:
                self.timekeeper.update(
                    engineID,
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                    timestamp=timestamp
                )

            return securityParameters, msgData[:]

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
        elif securityLevel.priv and user.priv is None:
            username = userName.decode()
            errmsg = f"Data privacy is disabled for user \"{username}\""
            raise UnsupportedSecLevel(errmsg)

        padding = user.auth.msgAuthenticationParameters
        if len(msgAuthenticationParameters.data) != len(padding):
            raise WrongDigest("Invalid signature length")

        wholeMsg = b''.join((
            msg.data[:msgAuthenticationParametersIndex],
            padding,
            msg.data[msgAuthenticationParametersIndex + len(padding):]
        ))

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

        if securityLevel.priv:
            try:
                payload = cast(PrivProtocol, user.priv).decrypt(
                    cast(bytes, OctetString.decode(msgData).data),
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                    cast(bytes, msgPrivacyParameters.data),
                )
            except ValueError as err:
                raise DecryptionError(str(err)) from err
        else:
            payload = msgData[:]

        return securityParameters, payload
