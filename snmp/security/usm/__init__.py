from time import time
from snmp.ber import decode
from snmp.types import *
from snmp.security.levels import *

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

class UserEntry:
    def __init__(self, engineID, name, auth=None, priv=None):
        self.engineID = engineID
        self.name = name
        self.auth = auth
        self.priv = priv

class SecureData:
    def __init__(self, data, user, securityLevel=noAuthNoPriv):
        self.scopedPDU = data
        self.securityEngineID = user.engineID
        self.securityLevel = securityLevel
        self.securityName = user.name

class EngineEntry:
    MAX_ENGINE_BOOTS = 0x7fffffff
    TIME_WINDOW_SIZE = 150

    def __init__(self, engineBoots=0, latestBootTime=None, authoritative=False):
        if latestBootTime is None:
            latestBootTime = time()

        self.authoritative = authoritative
        self.snmpEngineBoots = engineBoots
        self.latestBootTime = latestBootTime
        self.latestReceivedEngineTime = 0
        self.userTable = {}

    def addUser(self, user):
        self.userTable[user.name] = user

    def getUser(self, name):
        return self.userTable[name]

    def calculateEngineTime(self, timestamp):
        return int(timestamp - self.latestBootTime)

    @property
    def snmpEngineTime(self):
        return self.calculateEngineTime(time())

    def verifyTimeliness(self, msgEngineBoots, msgEngineTime, timestamp=None):
        if timestamp is None:
            timestamp = time()

        snmpEngineTime = self.calculateEngineTime(timestamp)
        withinTimeWindow = False

        if self.authoritative:
            if (msgEngineBoots == self.snmpEngineBoots
            and abs(snmpEngineTime - msgEngineTime) <= self.TIME_WINDOW_SIZE):
                withinTimeWindow = True
        elif msgEngineBoots == self.snmpEngineBoots:
            if msgEngineTime > snmpEngineTime:
                snmpEngineTime = msgEngineTime
                self.latestBootTime = timestamp - snmpEngineTime

            if snmpEngineTime > self.latestReceivedEngineTime:
                self.latestReceivedEngineTime = snmpEngineTime

            if snmpEngineTime - msgEngineTime <= self.TIME_WINDOW_SIZE:
                withinTimeWindow = True
        elif msgEngineBoots > self.snmpEngineBoots:
            self.snmpEngineBoots = msgEngineBoots
            self.latestBootTime = timestamp - msgEngineTime
            self.latestReceivedEngineTime = msgEngineTime
            withinTimeWindow = True

        if self.snmpEngineBoots == self.MAX_ENGINE_BOOTS:
            withinTimeWindow = False

        return withinTimeWindow

class SecurityModule:
    def __init__(self, *users):
        self.engineTable = {}

        for user in users:
            try:
                entry = self.engineTable[user.engineID]
            except KeyError:
                entry = EngineEntry()
                self.engineTable[user.engineID] = entry

            entry.addUser(user)

    def processIncomingMsg(self, msg, securityLevel, timestamp=None):
        if timestamp is None:
            timestamp = time()

        msgSecurityParameters, msgData = \
            OctetString.decode(msg, leftovers=True, copy=False)
        ptr = decode(msgSecurityParameters, expected=SEQUENCE)
        msgAuthoritativeEngineID, ptr = OctetString.decode(ptr, leftovers=True)
        msgAuthoritativeEngineBoots, ptr  = Integer.decode(ptr, leftovers=True)
        msgAuthoritativeEngineTime,  ptr  = Integer.decode(ptr, leftovers=True)
        msgUserName,              ptr = OctetString.decode(ptr, leftovers=True)

        msgAuthenticationParameters, ptr = \
            OctetString.decode(ptr, leftovers=True)
        msgAuthenticationParametersIndex = \
            ptr.start - len(msgAuthenticationParameters)
        msgPrivacyParameters = OctetString.decode(ptr)

        try:
            engine = self.engineTable[msgAuthoritativeEngineID]
        except KeyError as err:
            raise UnknownEngineID(msgAuthoritativeEngineID) from err

        try:
            user = engine.getUser(msgUserName)
        except KeyError as err:
            raise UnknownSecurityName(msgUserName) from err

        if not securityLevel.auth:
            return SecureData(msgData[:], user, securityLevel)
        elif user.auth is None:
            err = "Authentication is disabled for user {}".format(user.name)
            raise UnsupportedSecurityLevel(err)
        elif securityLevel.priv and user.priv is None:
            err = "Data privacy is disabled for user {}".format(user.name)
            raise UnsupportedSecurityLevel(err)

        wholeMsg = bytearray(msg.data)
        padding = user.auth.msgAuthenticationParameters
        if len(msgAuthenticationParameters) != len(padding):
            raise AuthenticationFailure("Invalid signature length")

        for i in range(len(msgAuthenticationParameters)):
            wholeMsg[msgAuthenticationParametersIndex + i] = padding[i]

        if user.auth.sign(wholeMsg) != msgAuthenticationParameters:
            raise AuthenticationFailure("Invalid signature")

        if not engine.verifyTimeliness(
                msgAuthoritativeEngineBoots,
                msgAuthoritativeEngineTime,
                timestamp=timestamp):
            raise NotInTimeWindow()

        if securityLevel.priv:
            payload = user.priv.decrypt(
                OctetString.decode(msgData),
                msgAuthoritativeEngineBoots,
                msgAuthoritativeEngineTime,
                msgPrivacyParameters
            )
        else:
            payload = msgData[:]

        return SecureData(payload, user, securityLevel)
