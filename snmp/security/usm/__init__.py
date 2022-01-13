__all__ = [
    "AuthenticationFailure", "NotInTimeWindow", "UnknownEngineID",
    "UnknownSecurityName", "UnsupportedSecurityLevel",
    "SecureData", "SecurityModule",
]

from time import time
from snmp.ber import decode, encode
from snmp.types import *
from snmp.security.levels import *
from snmp.utils import DummyLock

class AuthenticationFailure(ValueError):
    pass

class NotInTimeWindow(ValueError):
    pass

class UnknownEngineID(ValueError):
    pass

class UnknownSecurityName(ValueError):
    pass

class UnsupportedSecurityLevel(ValueError):
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
                raise UnknownEngineID(engineID) from err

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

    def addUser(self, engineID, userName, authProtocol=None, authSecret=None,
                privProtocol=None, privSecret=None, secret=b''):
        with self.lock:
            try:
                users = self.engines[engineID]
            except KeyError:
                users = {}
                self.engines[engineID] = users

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
                raise UnknownEngineID(engineID) from err

            return users[userName]

class SecureData:
    def __init__(self, data, engineID, userName, securityLevel=noAuthNoPriv):
        self.data = data
        self.securityEngineID = engineID
        self.securityLevel = securityLevel
        self.securityName = userName

class SecurityModule:
    MODEL = 3

    def __init__(self, lockType=DummyLock, engineID=None, *args, **kwargs):
        self.engineID = engineID
        self.timekeeper = TimeKeeper(lockType)
        self.users = UserTable(lockType)

        if self.engineID is not None:
            self.addEngine(self.engineID, *args, **kwargs)

    def addEngine(self, *args, **kwargs):
        self.timekeeper.addEngine(*args, **kwargs)

    def addUser(self, *args, **kwargs):
        self.users.addUser(*args, **kwargs)

    def prepareOutgoing(self, header, data, engineID,
                        securityName, securityLevel):
        if securityLevel.auth:
            try:
                user = self.users.getUser(engineID, securityName)
            except KeyError as err:
                raise UnknownSecurityName(securityName) from err

            if not user.auth:
                err = "Authentication is disabled for user {}".format(user.name)
                raise UnsupportedSecurityLevel(err)

            engineTimeParameters = self.timekeeper.getEngineTime(engineID)
            snmpEngineBoots, snmpEngineTime = engineTimeParameters
            msgAuthenticationParameters = user.auth.msgAuthenticationParameters
            msgPrivacyParameters = b''

            if securityLevel.priv:
                if not user.priv:
                    err = "Privacy is disabled for user {}".format(user.name)
                    raise UnsupportedSecurityLevel(err)

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
        except KeyError as err:
            raise UnknownSecurityName(userName) from err

        if user.auth is None:
            err = "Authentication is disabled for user {}".format(user.name)
            raise UnsupportedSecurityLevel(err)
        elif securityLevel.priv and user.priv is None:
            err = "Data privacy is disabled for user {}".format(user.name)
            raise UnsupportedSecurityLevel(err)

        padding = user.auth.msgAuthenticationParameters
        if len(msgAuthenticationParameters.data) != len(padding):
            raise AuthenticationFailure("Invalid signature length")

        wholeMsg = b''.join((
            msg.data[:msgAuthenticationParametersIndex],
            padding,
            msg.data[msgAuthenticationParametersIndex + len(padding):]
        ))

        if user.auth.sign(wholeMsg) != msgAuthenticationParameters.data:
            raise AuthenticationFailure("Invalid signature")

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

        if securityLevel.priv:
            payload = user.priv.decrypt(
                OctetString.decode(msgData).data,
                msgAuthoritativeEngineBoots.value,
                msgAuthoritativeEngineTime.value,
                msgPrivacyParameters.data
            )
        else:
            payload = msgData[:]

        return SecureData(payload, engineID, userName, securityLevel)
