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
    def __init__(self, name, auth=None, priv=None):
        self.name = name
        self.auth = auth
        self.priv = priv

class SecureData:
    def __init__(self, data, engineID, userName, securityLevel=noAuthNoPriv):
        self.scopedPDU = data
        self.securityEngineID = engineID
        self.securityLevel = securityLevel
        self.securityName = userName

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


        withinTimeWindow = False
        if self.authoritative:
            if msgEngineBoots == self.snmpEngineBoots:
                difference = self.calculateEngineTime(timestamp) - msgEngineTime
                if abs(difference) <= self.TIME_WINDOW_SIZE:
                    withinTimeWindow = True
        else:
            if msgEngineBoots > self.snmpEngineBoots:
                self.snmpEngineBoots = msgEngineBoots
                self.latestBootTime = timestamp
                self.latestReceivedEngineTime = 0

            if msgEngineBoots == self.snmpEngineBoots:
                if msgEngineTime > self.latestReceivedEngineTime:
                    self.latestBootTime = timestamp - msgEngineTime
                    self.latestReceivedEngineTime = msgEngineTime
                    withinTimeWindow = True
                else:
                    snmpEngineTime = self.calculateEngineTime(timestamp)
                    difference = snmpEngineTime - msgEngineTime
                    if difference <= self.TIME_WINDOW_SIZE:
                        withinTimeWindow = True

        if self.snmpEngineBoots == self.MAX_ENGINE_BOOTS:
            withinTimeWindow = False

        return withinTimeWindow

class SecurityModule:
    def __init__(self):
        self.engineTable = {}

    def addUser(self, engineID, userName, authProtocol=None, authSecret=None,
                privProtocol=None, privSecret=None, secret=b''):
        try:
            entry = self.engineTable[engineID]
        except KeyError:
            entry = EngineEntry()
            self.engineTable[engineID] = entry

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

        entry.addUser(UserEntry(userName, **kwargs))

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

        engineID = msgAuthoritativeEngineID.data
        userName = msgUserName.data

        if not securityLevel.auth:
            return SecureData(msgData[:], engineID, userName)

        try:
            engine = self.engineTable[engineID]
        except KeyError as err:
            raise UnknownEngineID(engineID) from err

        try:
            user = engine.getUser(userName)
        except KeyError as err:
            raise UnknownSecurityName(userName) from err

        if user.auth is None:
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

        return SecureData(payload, engineID, userName, securityLevel)
