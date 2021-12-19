from snmp.ber import ParseError
from snmp.types import *

class MessageFlags(Asn1Encodable):
    TYPE = OCTET_STRING
    AUTH_FLAG       = (1 << 0)
    PRIV_FLAG       = (1 << 1)
    REPORTABLE_FLAG = (1 << 2)
    ALL_FLAGS       = AUTH_FLAG | PRIV_FLAG | REPORTABLE_FLAG

    def __init__(self, byte=0):
        self.byte = byte & self.ALL_FLAGS

    @classmethod
    def deserialize(cls, data):
        try:
            return cls(data[0])
        except IndexError as err:
            raise ParseError("Missing flags")

    def serialize(self):
        return bytes([self.byte])

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
