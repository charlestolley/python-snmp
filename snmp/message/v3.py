from snmp.ber import ParseError, decode_identifier
from snmp.pdu.v2 import pduTypes
from snmp.security import SecurityLevel
from snmp.security.levels import noAuthNoPriv
from snmp.types import *
from snmp.utils import NumberGenerator, subbytes

class InvalidMessage(ValueError):
    pass

class UnknownSecurityModel(ValueError):
    pass

class MessageFlags(OctetString):
    MIN_SIZE = 1

    AUTH_FLAG       = (1 << 0)
    PRIV_FLAG       = (1 << 1)
    REPORTABLE_FLAG = (1 << 2)
    ALL_FLAGS       = AUTH_FLAG | PRIV_FLAG | REPORTABLE_FLAG

    def __init__(self, byte=0):
        self.byte = byte & self.ALL_FLAGS

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
            raise ParseError("Invalid PDU type: {}".format(identifier)) from err

        return cls(
            pduType.decode(data),
            contextEngineID=contextEngineID,
            contextName=contextName
        )

class MessagePreparer:
    VERSION = 3

    def __init__(self, security):
        self.generator = NumberGenerator(31, signed=False)
        self.security = security

    def prepareDataElements(self, msg):
        msgGlobalData, msg = HeaderData.decode(msg, leftovers=True)

        if msgGlobalData.securityModel != self.security.MODEL:
            raise UnknownSecurityModel(msgGlobalData.securityModel)

        try:
            securityLevel = SecurityLevel(
                auth=msgGlobalData.flags.authFlag,
                priv=msgGlobalData.flags.privFlag)
        except ValueError as err:
            raise InvalidMessage("Invalid msgFlags: {}".format(err)) from err

        secureData = self.security.processIncoming(msg, securityLevel)
        secureData.scopedPDU = ScopedPDU.decode(secureData.data, types=pduTypes)
        return secureData

    def prepareOutgoingMessage(self, pdu, engineID, userName,
                securityLevel=noAuthNoPriv, contextName=b''):
        scopedPDU = ScopedPDU(pdu, engineID, contextName=contextName)

        msgID = next(self.generator)
        flags = MessageFlags()
        flags.authFlag = securityLevel.auth
        flags.privFlag = securityLevel.priv
        flags.reportableFlag = True

        msgGlobalData = HeaderData(msgID, 1472, flags, self.security.MODEL)
        header = Integer(self.VERSION).encode() + msgGlobalData.encode()

        return self.security.prepareOutgoing(
            header,
            scopedPDU.encode(),
            engineID,
            userName,
            securityLevel,
        )
