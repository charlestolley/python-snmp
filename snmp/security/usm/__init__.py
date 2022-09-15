__all__ = [
    "InvalidEngineID", "InvalidUserName",
    "InvalidSecurityLevel", "SecurityModule",
]

import threading

from time import time
from snmp.ber import decode, encode
from snmp.exception import IncomingMessageError
from snmp.types import *
from snmp.security import SecurityModel, SecurityParameters
from snmp.security.levels import *
from snmp.utils import typename

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
    def __init__(self, engineBoots, latestBootTime=None, authenticated=False):
        if latestBootTime is None:
            latestBootTime = time()

        self.authenticated = authenticated
        self.snmpEngineBoots = engineBoots
        self.latestBootTime = latestBootTime
        self.latestReceivedEngineTime = 0

    def snmpEngineTime(self, timestamp):
        return int(timestamp - self.latestBootTime)

class TimeKeeper:
    MAX_ENGINE_BOOTS = (1 << 31) - 1
    TIME_WINDOW_SIZE = 150

    def __init__(self):
        self.lock = threading.Lock()
        self.table = {}

    def getEngineTime(self, engineID, timestamp=None):
        if timestamp is None:
            timestamp = time()

        with self.lock:
            try:
                entry = self.table[engineID]
            except KeyError:
                return 0, 0

            return entry.snmpEngineBoots, entry.snmpEngineTime(timestamp)

    def update(self, engineID, msgBoots=0, msgTime=0, timestamp=None):
        self.updateAndVerify(engineID, msgBoots, msgTime, False, timestamp)

    def updateAndVerify(self, engineID, msgBoots, msgTime,
                                auth=True, timestamp=None):
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

            if auth:
                entry.authenticated = True

            return withinTimeWindow

class Credentials:
    def __init__(self, auth=None, priv=None):
        self.auth = auth
        self.priv = priv

class UserTable:
    def __init__(self):
        self.engines = {}
        self.lock = threading.Lock()

    def addUser(self, engineID, userName, credentials):
        with self.lock:
            try:
                users = self.engines[engineID]
            except KeyError:
                users = dict()
                self.engines[engineID] = users

            users[userName] = credentials

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

class SecurityModule:
    MODEL = SecurityModel.USM

    def __init__(self, engineID=None):
        self.engineID = engineID
        self.timekeeper = TimeKeeper()
        self.users = UserTable()

        if self.engineID is not None:
            self.timekeeper.update(self.engineID)

    def addUser(self, engineID, userName,
                authProtocol=None, authKey=None,
                privProtocol=None, privKey=None):
        if authProtocol is None:
            credentials = Credentials()
        else:
            assert authKey is not None
            auth = authProtocol(authKey)

            if privProtocol is None:
                credentials = Credentials(auth)
            else:
                assert privKey is not None
                priv = privProtocol(privKey)

                credentials = Credentials(auth, priv)

        self.users.addUser(engineID, userName, credentials)

    def prepareOutgoing(self, header, data, engineID,
                        securityName, securityLevel):
        if securityLevel.auth:
            user = self.users.getUser(engineID, securityName)

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

                msgPrivacyParameters, ciphertext = user.priv.encrypt(
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
        securityParameters = SecurityParameters(engineID, userName)

        if not securityLevel.auth:
            self.timekeeper.update(
                engineID,
                msgAuthoritativeEngineBoots.value,
                msgAuthoritativeEngineTime.value,
                timestamp=timestamp
            )

            return securityParameters, msgData[:]

        try:
            user = self.users.getUser(engineID, userName)
        except InvalidEngineID as err:
            raise UnknownEngineID(engineID) from err
        except InvalidUserName as err:
            raise UnknownUserName(userName) from err

        if user.auth is None:
            userName = userName.decode()
            errmsg = f"Authentication is disabled for user \"{userName}\""
            raise UnsupportedSecLevel(errmsg)
        elif securityLevel.priv and user.priv is None:
            userName = userName.decode()
            errmsg = f"Data privacy is disabled for user \"{userName}\""
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

        return securityParameters, payload
