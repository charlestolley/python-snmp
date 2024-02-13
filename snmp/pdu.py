__all__ = [
    "NoSuchObject", "NoSuchInstance", "EndOfMibView",
    "VarBind", "VarBindList",
    "AnyPDU", "PDU", "BulkPDU",
    "GetRequestPDU", "GetNextRequestPDU", "GetBulkRequestPDU",
    "SetRequestPDU",
    "ResponsePDU", "ReportPDU",
    "InformRequestPDU", "SNMPv2TrapPDU",
    "Read", "Write", "Response", "Internal", "Notification", "Confirmed",
    "ErrorStatus", "ErrorResponse",
]

import enum

from snmp.asn1 import *
from snmp.ber import *
from snmp.exception import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import subbytes, typename

AnyPDU = Union["PDU", "BulkPDU"]
TPDU = TypeVar("TPDU", bound="PDU")
TBulkPDU = TypeVar("TBulkPDU", bound="BulkPDU")

@final
class NoSuchObject(Null):
    TAG = Tag(0, cls = Tag.Class.CONTEXT_SPECIFIC)

@final
class NoSuchInstance(Null):
    TAG = Tag(1, cls = Tag.Class.CONTEXT_SPECIFIC)

@final
class EndOfMibView(Null):
    TAG = Tag(2, cls = Tag.Class.CONTEXT_SPECIFIC)

@final
class VarBind(Sequence):
    TYPES = {
        cls.TAG: cls for cls in cast(Tuple[Primitive, ...], (
            Integer,
            OctetString,
            Null,
            OID,
            IpAddress,
            Counter32,
            Gauge32,
            TimeTicks,
            Opaque,
            Counter64,
            NoSuchObject,
            NoSuchInstance,
            EndOfMibView,
        ))
    }

    def __init__(self,
        name: Union[str, OID],
        value: Optional[ASN1] = None,
    ) -> None:
        if not isinstance(name, OID):
            name = OID.parse(name)

        if value is None:
            value = Null()

        self.name = name
        self.value = value

    def __iter__(self) -> Iterator[ASN1]:
        yield self.name
        yield self.value

    def __len__(self) -> int:
        return 2

    def __repr__(self) -> str:
        return f"{typename(self)}({self.name!r}, {self.value!r})"

    def __str__(self) -> str:
        return f"{self.name}: {self.value}"

    @classmethod
    def deserialize(cls, data: Asn1Data) -> "VarBind":
        name, data = cast(
            Tuple[OID, subbytes],
            OID.decode(data, leftovers=True),
        )

        identifier, data = decode(data)

        try:
            valueType = cls.TYPES[identifier]
        except KeyError as err:
            msg = "Invalid variable value type: {}"
            raise ParseError(msg.format(identifier)) from err

        return cls(name, valueType.deserialize(data))

@final
class VarBindList(Sequence):
    def __init__(self, *args: Union[str, OID, VarBind]) -> None:
        self.variables = tuple(
            var if isinstance(var, VarBind) else VarBind(var) for var in args
        )

    def __bool__(self) -> bool:
        return bool(self.variables)

    @overload
    def __getitem__(self, key: int) -> VarBind:
        ...

    @overload
    def __getitem__(self, key: slice) -> Tuple[VarBind, ...]:
        ...

    def __getitem__(self,
        key: Union[int, slice],
    ) -> Union[VarBind, Tuple[VarBind, ...]]:
        return self.variables[key]

    def __iter__(self) -> Iterator[VarBind]:
        return iter(self.variables)

    def __len__(self) -> int:
        return len(self.variables)

    def __repr__(self) -> str:
        args = ", ".join(repr(var) for var in self.variables)
        return f"{typename(self)}({args})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, indent: str = "") -> str:
        return "\n".join(f"{indent}{var}" for var in self.variables)

    @classmethod
    def deserialize(cls, data: Asn1Data) -> "VarBindList":
        objects = []

        while data:
            var, data = cast(
                Tuple[VarBind, subbytes],
                VarBind.decode(data, leftovers=True),
            )

            objects.append(var)

        return cls(*objects)

class ErrorStatus(enum.IntEnum):
    noError             = 0
    tooBig              = 1
    noSuchName          = 2
    badValue            = 3
    readOnly            = 4
    genErr              = 5
    noAccess            = 6
    wrongType           = 7
    wrongLength         = 8
    wrongEncoding       = 9
    wrongValue          = 10
    noCreation          = 11
    inconsistentValue   = 12
    resourceUnavailable = 13
    commitFailed        = 14
    undoFailed          = 15
    authorizationError  = 16
    notWritable         = 17
    inconsistentName    = 18

class PDU(Constructed):
    def __init__(self,
        *args: Union[str, OID, VarBind],
        requestID: int = 0,
        errorStatus: ErrorStatus = ErrorStatus.noError,
        errorIndex: int = 0,
        variableBindings: Optional[VarBindList] = None,
    ) -> None:
        self.requestID = requestID
        self.errorStatus = errorStatus
        self.errorIndex = errorIndex

        if variableBindings is None:
            self.variableBindings = VarBindList(*args)
        else:
            self.variableBindings = variableBindings

    def __iter__(self) -> Iterator[ASN1]:
        yield Integer(self.requestID)
        yield Integer(self.errorStatus)
        yield Integer(self.errorIndex)
        yield self.variableBindings

    def __len__(self) -> int:
        return 4

    def __repr__(self) -> str:
        arguments = []
        if self.requestID:
            arguments.append("requestID={}".format(self.requestID))

        if self.errorStatus:
            arguments.append("errorStatus={}".format(self.errorStatus))

        if self.errorIndex:
            arguments.append("errorIndex={}".format(self.errorIndex))

        arguments.append(f"variableBindings={self.variableBindings!r}")

        args = ", ".join(arguments)
        return f"{typename(self)}({args})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
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
            subindent, self.errorStatus.name,
            subindent, self.errorIndex,
            subindent, self.variableBindings.toString(subindent + tab)
        )

    @classmethod
    def deserialize(cls: Type[TPDU], data: Asn1Data) -> TPDU:
        _requestID, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        _errorStatus, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        _errorIndex, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        variableBindings = VarBindList.decode(data)

        requestID = _requestID.value
        errorStatus = _errorStatus.value
        errorIndex = _errorIndex.value

        try:
            errorStatus = ErrorStatus(errorStatus)
        except ValueError as err:
            msg = "Invalid errorStatus: {}"
            raise ParseError(msg.format(errorStatus)) from err

        if (errorStatus != ErrorStatus.noError
        and errorIndex < 0 or errorIndex > len(variableBindings)):
            msg = "Error index {} not valid with {} variable bindings"
            raise ParseError(msg.format(errorIndex, len(variableBindings)))

        return cls(
            requestID=requestID,
            errorStatus=errorStatus,
            errorIndex=errorIndex,
            variableBindings=variableBindings,
        )

class BulkPDU(Constructed):
    def __init__(self,
        *args: Union[str, OID, VarBind],
        requestID: int = 0,
        nonRepeaters: int = 0,
        maxRepetitions: int = 0,
        variableBindings: Optional[VarBindList] = None,
    ) -> None:
        self.requestID = requestID
        self.nonRepeaters = nonRepeaters
        self.maxRepetitions = maxRepetitions

        if variableBindings is None:
            self.variableBindings = VarBindList(*args)
        else:
            self.variableBindings = variableBindings

    def __iter__(self) -> Iterator[ASN1]:
        yield Integer(self.requestID)
        yield Integer(self.nonRepeaters)
        yield Integer(self.maxRepetitions)
        yield self.variableBindings

    def __len__(self) -> int:
        return 4

    def __repr__(self) -> str:
        arguments = []
        if self.requestID:
            arguments.append("requestID={}".format(self.requestID))

        if self.nonRepeaters:
            arguments.append("nonRepeaters={}".format(self.nonRepeaters))

        if self.maxRepetitions:
            arguments.append("maxRepetitions={}".format(self.maxRepetitions))

        arguments.append("variableBindings={}".format(repr(self.variableBindings)))

        args = ", ".join(arguments)
        return f"{typename(self)}({args})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
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
            indent, self.variableBindings.toString(tab * (depth + 2))
        )

    @classmethod
    def deserialize(cls: Type[TBulkPDU], data: Asn1Data) -> TBulkPDU:
        requestID, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        nonRepeaters, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        maxRepetitions, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

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

@final
class GetRequestPDU(PDU, Read, Confirmed):
    TAG = Tag(0, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class GetNextRequestPDU(PDU, Read, Confirmed):
    TAG = Tag(1, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class ResponsePDU(PDU, Response):
    TAG = Tag(2, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class SetRequestPDU(PDU, Write, Confirmed):
    TAG = Tag(3, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class GetBulkRequestPDU(BulkPDU, Read, Confirmed):
    TAG = Tag(5, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class InformRequestPDU(PDU, Notification, Confirmed):
    TAG = Tag(6, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class SNMPv2TrapPDU(PDU, Notification):
    TAG = Tag(7, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class ReportPDU(PDU, Response, Internal):
    TAG = Tag(8, True, Tag.Class.CONTEXT_SPECIFIC)

class ErrorResponse(SNMPException):
    def __init__(self,
        status: ErrorStatus,
        index: int,
        request: "AnyPDU",
    ) -> None:
        self.status = status
        self.cause: Union[VarBind, AnyPDU, int] = None

        details = ""
        if index == 0:
            self.cause = request
        else:
            try:
                self.cause = request.variableBindings[index-1]
            except IndexError:
                self.cause = index
            else:
                details = f": {self.cause.name}"

        super().__init__(f"{status.name}{details}")
