import threading
import weakref

from snmp.ber import ParseError, decode_identifier
from snmp.exception import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import noAuthNoPriv
from snmp.types import *
from snmp.utils import *
from . import MessageProcessingModel

pduTypes = {
    cls.TYPE: cls for cls in (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
        GetBulkRequestPDU,
        InformRequestPDU,
        SNMPv2TrapPDU,
        ReportPDU,
    )
}

class InvalidMessage(IncomingMessageError):
    pass

class LateResponse(IncomingMessageError):
    pass

class ResponseMismatch(IncomingMessageError):
    @classmethod
    def byField(cls, field):
        return cls(f"{field} does not match request")

class UnknownSecurityModel(IncomingMessageError):
    pass

class MessageFlags(OctetString):
    MIN_SIZE = 1

    AUTH_FLAG       = (1 << 0)
    PRIV_FLAG       = (1 << 1)
    REPORTABLE_FLAG = (1 << 2)
    ALL_FLAGS       = AUTH_FLAG | PRIV_FLAG | REPORTABLE_FLAG

    def __init__(self, byte=0):
        self.byte = byte & self.ALL_FLAGS

    def __repr__(self):
        return f"{typename(self)}({self.byte})"

    def __str__(self):
        flags = []
        if self.authFlag:
            flags.append("AUTH")

        if self.privFlag:
            flags.append("PRIV")

        if self.reportableFlag:
            flags.append("REPORTABLE")

        return f"<{','.join(flags)}>"

    @classmethod
    def parse(cls, data=b''):
        return cls(byte=data[0])

    @property
    def data(self):
        return bytes((self.byte,))

    @property
    def authFlag(self):
        return bool(self.byte & self.AUTH_FLAG)

    @property
    def privFlag(self):
        return bool(self.byte & self.PRIV_FLAG)

    @property
    def reportableFlag(self):
        return bool(self.byte & self.REPORTABLE_FLAG)

    @authFlag.setter
    def authFlag(self, value):
        if value:
            self.byte |= self.AUTH_FLAG
        else:
            self.byte &= ~self.AUTH_FLAG

    @privFlag.setter
    def privFlag(self, value):
        if value:
            self.byte |= self.PRIV_FLAG
        else:
            self.byte &= ~self.PRIV_FLAG

    @reportableFlag.setter
    def reportableFlag(self, value):
        if value:
            self.byte |= self.REPORTABLE_FLAG
        else:
            self.byte &= ~self.REPORTABLE_FLAG

class HeaderData(Sequence):
    def __init__(self, msgID, maxSize, flags, securityModel):
        self.id = msgID
        self.maxSize = maxSize
        self.flags = flags
        self.securityModel = securityModel

    def __repr__(self):
        args = (
            str(self.id),
            str(self.maxSize),
            repr(self.flags),
            str(SecurityModel(self.securityModel)),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self, depth=0, tab="    "):
        indent = tab * depth
        subindent = indent + tab
        securityModel = SecurityModel(self.securityModel)
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Message ID: {self.id}",
            f"{subindent}Sender Message Size Limit: {self.maxSize}",
            f"{subindent}Flags: {self.flags}",
            f"{subindent}Security Model: {securityModel.name}"
        ))

    @property
    def objects(self):
        yield Integer(self.id)
        yield Integer(self.maxSize)
        yield self.flags
        yield Integer(self.securityModel)

    @classmethod
    def deserialize(cls, data):
        msgID,      data = Integer      .decode(data, leftovers=True)
        msgMaxSize, data = Integer      .decode(data, leftovers=True)
        msgFlags,   data = MessageFlags .decode(data, leftovers=True)
        msgSecurityModel = Integer      .decode(data)

        if msgID.value < 0:
            raise ParseError("msgID may not be less than 0")
        elif msgMaxSize.value < 484:
            raise ParseError("msgMaxSize may not be less than 484")
        elif msgSecurityModel.value < 1:
            raise ParseError("msgSecurityModel may not be less than 1")

        return cls(
            msgID.value,
            msgMaxSize.value,
            msgFlags,
            msgSecurityModel.value
        )

class ScopedPDU(Sequence):
    def __init__(self, pdu, contextEngineID, contextName=b''):
        self.contextEngineID = contextEngineID
        self.contextName = contextName
        self.pdu = pdu

    def __repr__(self):
        args = (
            repr(self.pdu),
            repr(self.contextEngineID),
            f"contextName={repr(self.contextName)}"
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self, depth=0, tab="    "):
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Context Engine ID: {self.contextEngineID}",
            f"{subindent}Context Name: {self.contextName}",
            f"{self.pdu.__str__(depth=depth+1, tab=tab)}"
        ))

    @property
    def objects(self):
        yield OctetString(self.contextEngineID)
        yield OctetString(self.contextName)
        yield self.pdu

    @classmethod
    def deserialize(cls, data, types={}):
        contextEngineID, data = OctetString.decode(data, leftovers=True)
        contextName,     data = OctetString.decode(data, leftovers=True)

        identifier = decode_identifier(subbytes(data))

        try:
            pduType = types[identifier]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {identifier}") from err

        return cls(
            pduType.decode(data),
            contextEngineID=contextEngineID.data,
            contextName=contextName.data,
        )

class CacheEntry:
    def __init__(self, engineID, contextName, handle,
            securityName, securityModel, securityLevel):
        self.context = contextName
        self.engineID = engineID
        self.handle = handle
        self.securityName = securityName
        self.securityModel = securityModel
        self.securityLevel = securityLevel

class SNMPv3Message:
    def __init__(self, msgID, securityLevel, securityParameters, data):
        self.id = msgID
        self.securityLevel = securityLevel
        self.securityEngineID = securityParameters.securityEngineID
        self.securityName = securityParameters.securityName
        self.data = data

    def __repr__(self):
        args = (repr(member) for member in (
            self.id,
            self.securityLevel,
            SecurityParameters(self.securityEngineID, self.securityName),
            self.data,
        ))

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self, depth=0, tab="    "):
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Message ID: {self.id}",
            f"{subindent}Security Engine ID: {self.securityEngineID}",
            f"{subindent}Security Level: {self.securityLevel}",
            f"{subindent}Security Name: {self.securityName}",
            f"{self.data.__str__(depth+1, tab)}",
        ))

class MessageProcessor:
    VERSION = MessageProcessingModel.SNMPv3

    def __init__(self):
        self.cacheLock = threading.Lock()
        self.credentials = {}
        self.generator = NumberGenerator(31, signed=False)
        self.outstanding = {}

        self.securityLock = threading.Lock()
        self.defaultSecurityModel = None
        self.securityModules = {}

    def cache(self, entry, credentials=None):
        retry = 0
        while retry < 10:
            with self.cacheLock:
                msgID = next(self.generator)
                if msgID not in self.outstanding:
                    if credentials is not None:
                        self.credentials[msgID] = credentials

                    self.outstanding[msgID] = entry
                    return msgID

            retry += 1

        raise Exception("Failed to allocate message ID")

    def retrieve(self, msgID):
        with self.cacheLock:
            return self.outstanding[msgID]

    def uncache(self, msgID):
        with self.cacheLock:
            try:
                del self.outstanding[msgID]
            except KeyError:
                pass

    def secure(self, module, default=False):
        with self.securityLock:
            self.securityModules[module.MODEL] = module

            if default or self.defaultSecurityModel is None:
                self.defaultSecurityModel = module.MODEL

    def prepareDataElements(self, msg):
        msgGlobalData, msg = HeaderData.decode(msg, leftovers=True)

        with self.securityLock:
            try:
                securityModule = self.securityModules[
                    msgGlobalData.securityModel
                ]
            except KeyError as e:
                raise UnknownSecurityModel(msgGlobalData.securityModel) from e

        try:
            securityLevel = SecurityLevel(
                auth=msgGlobalData.flags.authFlag,
                priv=msgGlobalData.flags.privFlag)
        except ValueError as err:
            raise InvalidMessage(f"Invalid msgFlags: {err}") from err

        with self.cacheLock:
            credentials = self.credentials.get(msgGlobalData.id)

        security, data = \
            securityModule.processIncoming(msg, securityLevel, credentials)

        scopedPDU, _ = ScopedPDU.decode(data, types=pduTypes, leftovers=True)

        if isinstance(scopedPDU.pdu, Response):
            try:
                entry = self.retrieve(msgGlobalData.id)
            except KeyError as err:
                errmsg = f"Unknown msgID: {msgGlobalData.id}"
                raise ResponseMismatch(errmsg) from err

            handle = entry.handle()
            if handle is None:
                raise LateResponse("Handle has already been released")

            report = isinstance(scopedPDU.pdu, Internal)
            if not report and entry.securityLevel < securityLevel:
                raise ResponseMismatch.byField("Security Level")

            if not report and entry.engineID != security.securityEngineID:
                raise ResponseMismatch.byField("Security Engine ID")

            if entry.securityName != security.securityName:
                raise ResponseMismatch.byField("Security Name")

            if not report and entry.engineID != scopedPDU.contextEngineID:
                raise ResponseMismatch.byField("Context Engine ID")

            if entry.context != scopedPDU.contextName:
                raise ResponseMismatch.byField("Context Name")
        else:
            raise UnsupportedFeature("Received a non-response PDU type")

        message = \
            SNMPv3Message(msgGlobalData.id, securityLevel, security, scopedPDU)
        return message, handle

    def prepareOutgoingMessage(self, pdu, handle, engineID, securityName,
            securityLevel=noAuthNoPriv, securityModel=None, credentials=None,
            contextName=b''):

        with self.securityLock:
            if securityModel is None:
                securityModel = self.defaultSecurityModel

            try:
                securityModule = self.securityModules[securityModel]
            except KeyError as err:
                errmsg = f"Security Model {securityModel} has not been enabled"
                raise ValueError(errmsg) from err

        entry = CacheEntry(
            engineID,
            contextName,
            weakref.ref(handle),
            securityName,
            securityModel,
            securityLevel)

        msgID = self.cache(entry, credentials=credentials)
        handle.addCallback(self.uncache, msgID)

        flags = MessageFlags()
        flags.authFlag = securityLevel.auth
        flags.privFlag = securityLevel.priv
        flags.reportableFlag = isinstance(pdu, Confirmed)

        msgGlobalData = HeaderData(msgID, 1472, flags, securityModel)
        header = Integer(self.VERSION).encode() + msgGlobalData.encode()
        scopedPDU = ScopedPDU(pdu, engineID, contextName=contextName)

        return securityModule.prepareOutgoing(
            header,
            scopedPDU.encode(),
            engineID,
            securityName,
            securityLevel,
            credentials,
        )
