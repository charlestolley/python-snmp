__all__ = [
    "InvalidEngineID", "InvalidUserName", "InvalidSecurityLevel",
    "SecureData", "SecurityModule",
]

from time import time
from snmp.ber import decode, encode
from snmp.exception import IncomingMessageError
from snmp.types import *
from snmp.security.levels import *
from snmp.utils import DummyLock
from .. import SecurityModel

class UsmStatsError(IncomingMessageError):
    USM_STATS = OID.parse(".1.3.6.1.6.3.15.1.1")

    def __init__(self, msg):
        super().__init__(msg)
        self.oid = self.USM_STATS.extend(self.ERRNUM)

class UnsupportedSecLevel(UsmStatsError):
    ERRNUM = 1

class NotInTimeWindow(UsmStatsError):
    ERRNUM = 2

class UnknownUserName(UsmStatsError):
    ERRNUM = 3

class UnknownEngineID(UsmStatsError):
    ERRNUM = 4

class WrongDigest(UsmStatsError):
    ERRNUM = 5

class DecryptionError(UsmStatsError):
    ERRNUM = 6

class InvalidEngineID(ValueError):
    pass

class InvalidUserName(ValueError):
    pass

class InvalidSecurityLevel(ValueError):
    pass

class TimeEntry:
    def __init__(self, engineBoots, latestBootTime=None):
        if latestBootTime is None:
            latestBootTime = time()

        self.snmpEngineBoots = engineBoots
        self.latestBootTime = latestBootTime
        self.latestReceivedEngineTime = 0

    def snmpEngineTime(self, timestamp):
        return int(timestamp - self.latestBootTime)

class TimeKeeper:
    MAX_ENGINE_BOOTS = 0x7fffffff
    TIME_WINDOW_SIZE = 150

    def __init__(self, lockType):
        self.lock = lockType()
        self.table = {}

    def addEngine(self, engineID, engineBoots=0, bootTime=None):
        with self.lock:
            self.table[engineID] = TimeEntry(engineBoots, bootTime)

    def getEngineTime(self, engineID, timestamp=None):
        if timestamp is None:
            timestamp = time()

        with self.lock:
            try:
                entry = self.table[engineID]
            except KeyError:
                return 0, 0

            return entry.snmpEngineBoots, entry.snmpEngineTime(timestamp)

    def verifyTimeliness(self, engineID, msgBoots, msgTime,
                        authoritative=False, timestamp=None):
        if timestamp is None:
            timestamp = time()

        withinTimeWindow = False
        with self.lock:
            try:
                entry = self.table[engineID]
            except KeyError as err:
                raise InvalidEngineID(engineID) from err

            if authoritative:
                if msgBoots == entry.snmpEngineBoots:
                    difference = entry.snmpEngineTime(timestamp) - msgTime
                    if abs(difference) < self.TIME_WINDOW_SIZE:
                        withinTimeWindow = True
            else:
                if msgBoots > entry.snmpEngineBoots:
                    entry.snmpEngineBoots = msgBoots
                    entry.latestBootTime = timestamp
                    entry.latestReceivedEngineTime = 0

                if msgBoots == entry.snmpEngineBoots:
                    if msgTime > entry.latestReceivedEngineTime:
                        entry.latestBootTime = timestamp - msgTime
                        entry.latestReceivedEngineTime = msgTime
                        withinTimeWindow = True
                    else:
                        snmpEngineTime = entry.snmpEngineTime(timestamp)
                        difference = snmpEngineTime - msgTime
                        if difference <= self.TIME_WINDOW_SIZE:
                            withinTimeWindow = True

            if entry.snmpEngineBoots == self.MAX_ENGINE_BOOTS:
                withinTimeWindow = False

        return withinTimeWindow

class UserEntry:
    def __init__(self, name, auth=None, priv=None):
        self.name = name
        self.auth = auth
        self.priv = priv

class UserTable:
    def __init__(self, lockType):
        self.engines = {}
        self.lock = lockType()

    def addEngine(self, engineID):
        with self.lock:
            if engineID not in self.engines:
                self.engines[engineID] = {}

    def addUser(self, engineID, userName, authProtocol=None, authSecret=None,
                privProtocol=None, privSecret=None, secret=b''):
        with self.lock:
            try:
                users = self.engines[engineID]
            except KeyError as err:
                raise InvalidEngineID(engineID) from err

            if userName not in users:
                kwargs = dict()
                if authProtocol is not None:
                    if authSecret is None:
                        authSecret = secret

                    authKey = authProtocol.localize(authSecret, engineID)
                    kwargs["auth"] = authProtocol(authKey)

                    if privProtocol is not None:
                        if privSecret is None:
                            privSecret = secret

                        privKey = authProtocol.localize(privSecret, engineID)
                        kwargs["priv"] = privProtocol(privKey)

                users[userName] = UserEntry(userName, **kwargs)

    def getUser(self, engineID, userName):
        with self.lock:
            try:
                users = self.engines[engineID]
            except KeyError as err:
                raise InvalidEngineID(engineID) from err

            try:
                return users[userName]
            except KeyError as err:
                raise InvalidUserName(userName) from err

class SecureData:
    def __init__(self, data, engineID, userName, securityLevel=noAuthNoPriv):
        self.data = data
        self.securityEngineID = engineID
        self.securityLevel = securityLevel
        self.securityName = userName

class SecurityModule:
    MODEL = SecurityModel.USER_BASED

    def __init__(self, lockType=DummyLock, engineID=None, *args, **kwargs):
        self.engineID = engineID
        self.timekeeper = TimeKeeper(lockType)
        self.users = UserTable(lockType)

        if self.engineID is not None:
            self.addEngine(self.engineID, *args, **kwargs)

    def addEngine(self, engineID, *args, **kwargs):
        self.timekeeper.addEngine(engineID, *args, **kwargs)
        self.users.addEngine(engineID)

    def addUser(self, *args, **kwargs):
        self.users.addUser(*args, **kwargs)

    def prepareOutgoing(self, header, data, engineID,
                        securityName, securityLevel):
        if securityLevel.auth:
            user = self.users.getUser(engineID, securityName)

            if not user.auth:
                err = "Authentication is disabled for user {}".format(user.name)
                raise InvalidSecurityLevel(err)

            engineTimeParameters = self.timekeeper.getEngineTime(engineID)
            snmpEngineBoots, snmpEngineTime = engineTimeParameters
            msgAuthenticationParameters = user.auth.msgAuthenticationParameters
            msgPrivacyParameters = b''

            if securityLevel.priv:
                if not user.priv:
                    err = "Privacy is disabled for user {}".format(user.name)
                    raise InvalidSecurityLevel(err)

                msgPrivacyParameters = user.priv.msgPrivacyParameters
                data = OctetString(user.priv.encrypt(
                    data,
                    snmpEngineBoots,
                    snmpEngineTime,
                    msgPrivacyParameters
                )).encode()

        else:
            if engineID == self.engineID:
                engineTimeParameters = self.timekeeper.getEngineTime(engineID)
                snmpEngineBoots, snmpEngineTime = engineTimeParameters
            else:
                snmpEngineBoots = 0
                snmpEngineTime = 0

            msgAuthenticationParameters = b''
            msgPrivacyParameters = b''

        encodedPrivacyParameters = OctetString(msgPrivacyParameters).encode()
        securityParameters = encode(
            SEQUENCE,
            b''.join((
                OctetString(engineID).encode(),
                Integer(snmpEngineBoots).encode(),
                Integer(snmpEngineTime).encode(),
                OctetString(securityName).encode(),
                OctetString(msgAuthenticationParameters).encode(),
                encodedPrivacyParameters,
            ))
        )

        msgSecurityParameters = OctetString(securityParameters).encode()
        body = b''.join((header, msgSecurityParameters, data))
        wholeMsg = encode(SEQUENCE, body)

        if securityLevel.auth:
            signature = user.auth.sign(wholeMsg)
            endIndex = len(wholeMsg) - len(data) - len(encodedPrivacyParameters)
            startIndex = endIndex - len(signature)
            wholeMsg = b''.join((
                wholeMsg[:startIndex],
                signature,
                wholeMsg[endIndex:]
            ))

        return wholeMsg

    def processIncoming(self, msg, securityLevel, timestamp=None):
        if timestamp is None:
            timestamp = time()

        msgSecurityParameters, msgData = \
            OctetString.decode(msg, leftovers=True, copy=False)
        ptr = decode(msgSecurityParameters.data, expected=SEQUENCE, copy=False)
        msgAuthoritativeEngineID, ptr = OctetString.decode(ptr, leftovers=True)
        msgAuthoritativeEngineBoots, ptr  = Integer.decode(ptr, leftovers=True)
        msgAuthoritativeEngineTime,  ptr  = Integer.decode(ptr, leftovers=True)
        msgUserName,              ptr = OctetString.decode(ptr, leftovers=True)

        msgAuthenticationParameters, ptr = \
            OctetString.decode(ptr, leftovers=True)
        msgAuthenticationParametersIndex = \
            ptr.start - len(msgAuthenticationParameters.data)
        msgPrivacyParameters = OctetString.decode(ptr)

        engineID = msgAuthoritativeEngineID.data
        userName = msgUserName.data

        if not securityLevel.auth:
            return SecureData(msgData[:], engineID, userName)

        try:
            user = self.users.getUser(engineID, userName)
        except InvalidUserName as err:
            raise UnknownUserName(userName) from err

        if user.auth is None:
            err = "Authentication is disabled for user {}".format(user.name)
            raise UnsupportedSecLevel(err)
        elif securityLevel.priv and user.priv is None:
            err = "Data privacy is disabled for user {}".format(user.name)
            raise UnsupportedSecLevel(err)

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
            if not self.timekeeper.verifyTimeliness(
                    engineID,
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                    authoritative=(engineID == self.engineID),
                    timestamp=timestamp):
                raise NotInTimeWindow(
                    engineID,
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                )
        except InvalidEngineID as err:
            raise UnknownEngineID(engineID) from err

        if securityLevel.priv:
            try:
                payload = user.priv.decrypt(
                    OctetString.decode(msgData).data,
                    msgAuthoritativeEngineBoots.value,
                    msgAuthoritativeEngineTime.value,
                    msgPrivacyParameters.data
                )
            except ValueError as err:
                raise DecryptionError(str(err)) from err
        else:
            payload = msgData[:]

        return SecureData(payload, engineID, userName, securityLevel)
