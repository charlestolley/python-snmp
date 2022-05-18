__all__ = [
    "NoSuchObject", "NoSuchInstance", "EndOfMibView",
    "VarBind", "VarBindList", "PDU", "pduTypes",
    "GetRequestPDU", "GetNextRequestPDU", "ResponsePDU", "SetRequestPDU",
    "GetBulkRequestPDU", "InformRequestPDU", "TrapPDU", "ReportPDU",
    "Read", "Write", "Response", "Internal", "Notification", "Confirmed",
]

import enum
from snmp.ber import *
from snmp.smi.v2 import *
from snmp.types import *
from snmp.utils import subbytes, typename

class NoSuchObject(Null):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_PRIMITIVE, 0)

class NoSuchInstance(Null):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_PRIMITIVE, 1)

class EndOfMibView(Null):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_PRIMITIVE, 2)

class VarBind(Sequence):
    TYPES = {
        cls.TYPE: cls for cls in (
            Integer,
            OctetString,
            Null,
            OID,
            IpAddress,
            Counter32,
            Unsigned32,
            TimeTicks,
            Opaque,
            Counter64,
            NoSuchObject,
            NoSuchInstance,
            EndOfMibView,
        )
    }

    def __init__(self, name, value=None):
        if not isinstance(name, OID):
            name = OID.parse(name)

        if value is None:
            value = Null()

        self.name = name
        self.value = value

    def __iter__(self):
        return self.objects

    def __len__(self):
        return 2

    def __repr__(self):
        args = ", ".join((repr(self.name), repr(self.value)))
        return "{}({})".format(typename(self), args)

    def __str__(self):
        return "{}: {}".format(self.name, self.value)

    @property
    def objects(self):
        yield self.name
        yield self.value

    @classmethod
    def deserialize(cls, data):
        name, data = OID.decode(data, leftovers=True)
        identifier, data = decode(subbytes(data))

        try:
            valueType = cls.TYPES[identifier]
        except KeyError as err:
            msg = "Invalid variable value type: {}"
            raise ParseError(msg.format(identifier)) from err

        return cls(name, valueType.deserialize(data))

class VarBindList(Sequence):
    def __init__(self, *args):
        self.variables = [None] * len(args)
        for i, var in enumerate(args):
            if not isinstance(var, VarBind):
                var = VarBind(var)
            self.variables[i] = var

    def __bool__(self):
        return bool(self.variables)

    def __getitem__(self, key):
        return self.variables[key]

    def __iter__(self):
        return iter(self.variables)

    def __len__(self):
        return len(self.variables)

    def __repr__(self):
        args = ", ".join(repr(var) for var in self.variables)
        return "{}({})".format(typename(self), args)

    def __str__(self, indent=""):
        return "\n".join("{}{}".format(indent, var) for var in self.variables)

    @property
    def objects(self):
        return self.variables

    @classmethod
    def deserialize(cls, data):
        objects = []

        while data:
            var, data = VarBind.decode(data, leftovers=True)
            objects.append(var)

        return cls(*objects)

class PDU(Constructed):
    class ErrorStatus(enum.IntEnum):
        noError             = 0
        tooBig              = enum.auto()
        noSuchName          = enum.auto()
        badValue            = enum.auto()
        readOnly            = enum.auto()
        genErr              = enum.auto()
        noAccess            = enum.auto()
        wrongType           = enum.auto()
        wrongLength         = enum.auto()
        wrongEncoding       = enum.auto()
        wrongValue          = enum.auto()
        noCreation          = enum.auto()
        inconsistentValue   = enum.auto()
        resourceUnavailable = enum.auto()
        commitFailed        = enum.auto()
        undoFailed          = enum.auto()
        authorizationError  = enum.auto()
        notWritable         = enum.auto()
        inconsistentName    = enum.auto()

    def __init__(self, *args, requestID=0, errorStatus=0,
                    errorIndex=0, variableBindings=None):
        self.requestID = requestID
        self.errorStatus = errorStatus
        self.errorIndex = errorIndex

        if variableBindings is None:
            self.variableBindings = VarBindList(*args)
        else:
            self.variableBindings = variableBindings

    def __len__(self):
        return 4

    def __repr__(self):
        args = []
        if self.requestID:
            args.append("requestID={}".format(self.requestID))

        if self.errorStatus:
            args.append("errorStatus={}".format(self.errorStatus))

        if self.errorIndex:
            args.append("errorIndex={}".format(self.errorIndex))

        args.append("variableBindings={}".format(repr(self.variableBindings)))
        return "{}({})".format(typename(self), ", ".join(args))

    def __str__(self, depth=0, tab="    "):
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            "{}{}:",
            "{}Request ID: {}",
            "{}Error Status: {}",
            "{}Error Index: {}",
            "{}Variable Bindings:",
            "{}"
        )).format(
            indent, typename(self),
            subindent, self.requestID,
            subindent, self.errorStatus,
            subindent, self.errorIndex,
            subindent, self.variableBindings.__str__(subindent + tab)
        )

    @property
    def objects(self):
        yield Integer(self.requestID)
        yield Integer(self.errorStatus)
        yield Integer(self.errorIndex)
        yield self.variableBindings

    @classmethod
    def deserialize(cls, data):
        requestID,   data = Integer.decode(data, leftovers=True)
        errorStatus, data = Integer.decode(data, leftovers=True)
        errorIndex,  data = Integer.decode(data, leftovers=True)
        variableBindings = VarBindList.decode(data)

        requestID = requestID.value
        errorStatus = errorStatus.value
        errorIndex = errorIndex.value

        try:
            errorStatus = cls.ErrorStatus(errorStatus)
        except ValueError as err:
            msg = "Invalid errorStatus: {}"
            raise ParseError(msg.format(errorStatus)) from err

        if errorStatus != cls.ErrorStatus.noError:
            if errorIndex < 0 or errorIndex > len(variableBindings):
                msg = "Error index {} not valid with {} variable bindings"
                raise ParseError(msg.format(errorIndex, len(variableBindings)))

        return cls(
            requestID=requestID,
            errorStatus=errorStatus,
            errorIndex=errorIndex,
            variableBindings=variableBindings,
        )

class BulkPDU(Constructed):
    def __init__(self, *args, requestID=0, nonRepeaters=0,
                    maxRepetitions=0, variableBindings=None):
        self.requestID = requestID
        self.nonRepeaters = nonRepeaters
        self.maxRepetitions = maxRepetitions

        if variableBindings is None:
            self.variableBindings = VarBindList(*args)
        else:
            self.variableBindings = variableBindings

    def __len__(self):
        return 4

    def __repr__(self):
        args = []
        if self.requestID:
            args.append("requestID={}".format(self.requestID))

        if self.nonRepeaters:
            args.append("nonRepeaters={}".format(self.nonRepeaters))

        if self.maxRepetitions:
            args.append("maxRepetitions={}".format(self.maxRepetitions))

        args.append("variableBindings={}".format(repr(self.variableBindings)))
        return "{}({})".format(typename(self), ", ".join(args))

    def __str__(self, depth=0, tab="    "):
        indent = tab * (depth + 1)
        return "\n".join((
            "{}:",
            "{}Request ID: {}",
            "{}Non-Repeaters: {}",
            "{}Max Repetitions: {}",
            "{}Variable Bindings:",
            "{}"
        )).format(
            typename(self),
            indent, self.requestID,
            indent, self.nonRepeaters,
            indent, self.maxRepetitions,
            indent, self.variableBindings.__str__(tab * (depth + 2))
        )

    @property
    def objects(self):
        yield Integer(self.requestID)
        yield Integer(self.nonRepeaters)
        yield Integer(self.maxRepetitions)
        yield self.variableBindings

    @classmethod
    def deserialize(cls, data):
        requestID,   data = Integer.decode(data, leftovers=True)
        nonRepeaters, data = Integer.decode(data, leftovers=True)
        maxRepetitions,  data = Integer.decode(data, leftovers=True)
        variableBindings = VarBindList.decode(data)

        if nonRepeaters.value < 0:
            raise ParseError("nonRepeaters may not be less than 0")
        elif maxRepetitions.value < 0:
            raise ParseError("maxRepetitions may not be less than 0")

        return cls(
            requestID=requestID.value,
            nonRepeaters=nonRepeaters.value,
            maxRepetitions=maxRepetitions.value,
            variableBindings=variableBindings,
        )

class Read:
    pass

class Write:
    pass

class Response:
    pass

class Notification:
    pass

class Internal:
    pass

class Confirmed:
    pass

class GetRequestPDU(PDU, Read, Confirmed):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 0)

class GetNextRequestPDU(PDU, Read, Confirmed):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 1)

class ResponsePDU(PDU, Response):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 2)

class SetRequestPDU(PDU, Write, Confirmed):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 3)

class GetBulkRequestPDU(BulkPDU, Read, Confirmed):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 5)

class InformRequestPDU(PDU, Notification, Confirmed):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 6)

class TrapPDU(PDU, Notification):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 7)

class ReportPDU(PDU, Response, Internal):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 8)

pduTypes = {
    cls.TYPE: cls for cls in (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
        GetBulkRequestPDU,
        InformRequestPDU,
        TrapPDU,
        ReportPDU,
    )
}
