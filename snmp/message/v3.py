from snmp.ber import ParseError
from snmp.types import *

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
