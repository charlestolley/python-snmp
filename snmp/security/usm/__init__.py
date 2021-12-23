from time import time
from snmp.ber import decode, encode
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
    def __init__(self):
        self.engineTable = {}

    def addUser(self, user):
        try:
            entry = self.engineTable[user.engineID]
        except KeyError:
            entry = EngineEntry()
            self.engineTable[user.engineID] = entry

        entry.addUser(user)

    def generateRequestMsg(self, header, data, engineID,
                            securityName, securityLevel):
        if securityLevel.auth:
            try:
                engine = self.engineTable[engineID]
            except KeyError as err:
                raise UnknownEngineID(engineID) from err

            try:
                user = engine.getUser(securityName)
            except KeyError as err:
                raise UnknownSecurityName(securityName) from err

            if not user.auth:
                err = "Authentication is disabled for user {}".format(user.name)
                raise UnsupportedSecurityLevel(err)

            snmpEngineBoots = engine.snmpEngineBoots
            snmpEngineTime = engine.snmpEngineTime
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
            wholeMsg = wholeMsg[:startIndex] + signature + wholeMsg[endIndex:]

        return wholeMsg

    def processIncomingMsg(self, msg, securityLevel, timestamp=None):
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

        try:
            engine = self.engineTable[msgAuthoritativeEngineID.data]
        except KeyError as err:
            raise UnknownEngineID(msgAuthoritativeEngineID.data) from err

        try:
            user = engine.getUser(msgUserName.data)
        except KeyError as err:
            raise UnknownSecurityName(msgUserName.data) from err

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
        if len(msgAuthenticationParameters.data) != len(padding):
            raise AuthenticationFailure("Invalid signature length")

        for i in range(len(msgAuthenticationParameters.data)):
            wholeMsg[msgAuthenticationParametersIndex + i] = padding[i]

        if user.auth.sign(wholeMsg) != msgAuthenticationParameters.data:
            raise AuthenticationFailure("Invalid signature")

        if not engine.verifyTimeliness(
                msgAuthoritativeEngineBoots.value,
                msgAuthoritativeEngineTime.value,
                timestamp=timestamp):
            raise NotInTimeWindow()

        if securityLevel.priv:
            payload = user.priv.decrypt(
                OctetString.decode(msgData).data,
                msgAuthoritativeEngineBoots.value,
                msgAuthoritativeEngineTime.value,
                msgPrivacyParameters.data
            )
        else:
            payload = msgData[:]

        return SecureData(payload, user, securityLevel)
