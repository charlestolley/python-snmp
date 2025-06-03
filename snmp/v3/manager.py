__all__ = ["SNMPv3Manager"]

import collections

from snmp.exception import *
from snmp.pdu import *
from snmp.security.levels import *
from snmp.security.usm.stats import *
from snmp.smi import *
from snmp.v3.message import SecurityName

class UnhandledReport(IncomingMessageError):
    pass

class SNMPv3Manager:
    def __init__(self,
        director,
        usm,
        channel,
        namespace,
        defaultUserName,
        defaultSecurityLevel,
        autowait,
        engineID = None,
    ):
        self.director = director
        self.usm = usm
        self.channel = channel
        self.namespace = namespace
        self.defaultUserName = defaultUserName.encode()
        self.defaultSecurityLevel = defaultSecurityLevel
        self.autowait = autowait
        self.engineID = engineID

        self.args = {}

        self.auth = False
        self.synchronized = False
        self.discoveryHandle = None
        self.synchronizationHandle = None
        self.unsent = collections.deque()

    def initiateDiscovery(self, timeout):
        self.discoveryHandle = self.director.openRequest(self, timeout)
        self.director.sendRequest(
            self.discoveryHandle.requestID,
            self.channel,
            b"",
            GetRequestPDU(),
            b"",
            noAuthNoPriv,
            b"",
            self.namespace,
            timeout,
        )

        self.discoveryHandle.addCallback(self.onRequestClosed)

    def sendNext(self):
        requestID = self.unsent.popleft()

        try:
            args = self.args[requestID]
        except KeyError:
            return None

        return self.director.sendRequest(
            requestID,
            self.channel,
            self.engineID,
            *args,
        )

    def onRequestClosed(self, requestID):
        if (self.discoveryHandle is not None
        and requestID == self.discoveryHandle.requestID):
            self.discoveryHandle = None

            if self.engineID is None and self.unsent:
                refreshPeriod = self.args[self.unsent[0]][5]
                self.initiateDiscovery(refreshPeriod)

        elif requestID in self.args:
            if (self.synchronizationHandle is not None
            and requestID == self.synchronizationHandle.requestID):
                self.synchronizationHandle = None

                if not self.synchronized and self.unsent:
                    self.synchronizationHandle = self.sendNext()

            try:
                self.unsent.remove(requestID)
            except ValueError:
                pass

            self.args.pop(requestID)

    def processReport(self, report, engineID, auth):
        sendAll = False
        exception = None

        if self.engineID is None:
            self.engineID = engineID

            if (self.discoveryHandle is not None
            and report.requestID == self.discoveryHandle.requestID):
                sendAll = True
                self.director.resetRequest(report.requestID)
                self.discoveryHandle = None

        if not self.synchronized:
            self.synchronized = True

            if (self.synchronizationHandle is not None
            and report.requestID == self.synchronizationHandle.requestID):
                sendAll = True
                self.director.resetRequest(report.requestID)
                self.synchronizationHandle = None

        try:
            vb = report.variableBindings[0]
        except IndexError:
            oid = OID()
        else:
            oid = vb.name

        if oid == usmStatsUnknownEngineIDsInstance:
            if report.requestID in self.args:
                if auth or not self.auth:
                    self.engineID = engineID
                    self.director.resetRequest(report.requestID)

                self.director.sendRequest(
                    report.requestID,
                    self.channel,
                    engineID,
                    *self.args[report.requestID],
                )
        elif oid == usmStatsNotInTimeWindowsInstance:
            if report.requestID in self.args:
                self.director.sendRequest(
                    report.requestID,
                    self.channel,
                    engineID,
                    *self.args[report.requestID],
                )
        elif oid == usmStatsUnsupportedSecLevelsInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = UnsupportedSecurityLevel()
            else:
                securityLevel = args[2]
                exception = UnsupportedSecurityLevel(securityLevel)
        elif oid == usmStatsUnknownUserNamesInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = UnknownUserName()
            else:
                userName = args[3]

                try:
                    user = userName.decode()
                except UnicodeDecodeError:
                    exception = UnknownUserName(userName)
                else:
                    exception = UnknownUserName(user)

        elif oid == usmStatsWrongDigestsInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = WrongDigest()
            else:
                userName = args[3]

                try:
                    user = userName.decode()
                except UnicodeDecodeError:
                    exception = WrongDigest(userName)
                else:
                    exception = WrongDigest(user)
        elif oid == usmStatsDecryptionErrorsInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = DecryptionError()
            else:
                userName = args[3]

                try:
                    user = userName.decode()
                except UnicodeDecodeError:
                    exception = DecryptionError(userName)
                else:
                    exception = DecryptionError(user)
        else:
            exception = UnhandledReport(report)

        if auth and not self.auth:
            self.auth = True

        if sendAll:
            while self.unsent:
                self.sendNext()

        return exception

    def processResponse(self, response, engineID, auth):
        if auth:
            self.engineID = engineID

            if not self.auth:
                self.auth = True

        if not self.synchronized:
            self.synchronized = True

            if self.synchronizationHandle is not None:
                if response.requestID == self.synchronizationHandle.requestID:
                    self.synchronizationHandle = None
                elif self.synchronizationHandle.requestID in self.args:
                    self.director.sendRequest(
                        self.synchronizationHandle.requestID,
                        self.channel,
                        engineID,
                        *self.args[self.synchronizationHandle.requestID],
                    )

                while self.unsent:
                    self.sendNext()

        return True

    def makeRequest(self,
        pdu: AnyPDU,
        contextName = b"",
        securityLevel = None,
        user = None,
        wait = None,
        timeout = 10.0,
        refreshPeriod = 1.0,
    ):
        if securityLevel is None:
            securityLevel = self.defaultSecurityLevel

        if user is None:
            userName = self.defaultUserName
        else:
            userName = user.encode()

        if wait is None:
            wait = self.autowait

        handle = self.director.openRequest(self, timeout)

        args = (
            pdu,
            contextName,
            securityLevel,
            userName,
            self.namespace,
            refreshPeriod,
        )

        self.args[handle.requestID] = args

        send = True
        if self.engineID is None:
            if self.discoveryHandle is None:
                self.initiateDiscovery(refreshPeriod)

            send = False
        else:
            if securityLevel.auth and not self.synchronized:
                if self.synchronizationHandle is None:
                    self.synchronizationHandle = handle
                else:
                    send = False

        if send:
            self.director.sendRequest(
                handle.requestID,
                self.channel,
                self.engineID,
                *args,
            )
        else:
            self.unsent.append(handle.requestID)

        handle.addCallback(self.onRequestClosed)

        if wait:
            return handle.wait()
        else:
            return handle

    def get(self, *oids, **kwargs):
        pdu = GetRequestPDU(*oids)
        return self.makeRequest(pdu, **kwargs)

    def getBulk(self, *oids, nonRepeaters=0, maxRepetitions=0, **kwargs):
        pdu = GetBulkRequestPDU(*oids)
        return self.makeRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.makeRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        pdu = SetRequestPDU(*(VarBind(*vb) for vb in varbinds))
        return self.makeRequest(pdu, **kwargs)
