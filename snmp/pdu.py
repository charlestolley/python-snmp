__all__ = [
    "NoSuchObject", "NoSuchInstance", "EndOfMibView",
    "VarBind", "VarBindList",
    "AnyPDU", "PDU", "BulkPDU",
    "GetRequestPDU", "GetNextRequestPDU", "GetBulkRequestPDU",
    "SetRequestPDU",
    "ResponsePDU", "ReportPDU",
    "InformRequestPDU", "SNMPv2TrapPDU",
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
        name, data = OID.decode(data)
        tag, _ = Tag.decode(data)

        try:
            valueType = cls.TYPES[tag]
        except KeyError as err:
            errmsg = f"Invalid variable value type: {tag}"
            raise ParseError(errmsg, data) from err

        return cls(name, valueType.decodeExact(data))

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
            var, data = VarBind.decode(data)
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
    READ_CLASS: ClassVar[bool] = False
    WRITE_CLASS: ClassVar[bool] = False
    RESPONSE_CLASS: ClassVar[bool] = False
    NOTIFICATION_CLASS: ClassVar[bool] = False
    INTERNAL_CLASS: ClassVar[bool] = False
    CONFIRMED_CLASS: ClassVar[bool] = False

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

    def withRequestID(self: TPDU, requestID: int) -> TPDU:
        return self.__class__(
            requestID=requestID,
            errorStatus=self.errorStatus,
            errorIndex=self.errorIndex,
            variableBindings=self.variableBindings,
        )

    @classmethod
    def deserialize(cls: Type[TPDU], data: Asn1Data) -> TPDU:
        _requestID, errorStatusData     = Integer.decode(data)
        _errorStatus, errorIndexData    = Integer.decode(errorStatusData)
        _errorIndex, data               = Integer.decode(errorIndexData)
        variableBindings                = VarBindList.decodeExact(data)

        requestID = _requestID.value
        errorStatus = _errorStatus.value
        errorIndex = _errorIndex.value

        try:
            errorStatus = ErrorStatus(errorStatus)
        except ValueError as err:
            msg = f"Invalid errorStatus: {errorStatus}"
            raise ParseError(msg, errorStatusData, errorIndexData) from err

        if (errorStatus != ErrorStatus.noError
        and (errorIndex < 0 or errorIndex > len(variableBindings))):
            msg = f"Error index {errorIndex} not valid" \
                f" with {len(variableBindings)} variable bindings"
            raise ParseError(msg, errorIndexData, data)

        return cls(
            requestID=requestID,
            errorStatus=errorStatus,
            errorIndex=errorIndex,
            variableBindings=variableBindings,
        )

class BulkPDU(Constructed):
    READ_CLASS: ClassVar[bool] = False
    WRITE_CLASS: ClassVar[bool] = False
    RESPONSE_CLASS: ClassVar[bool] = False
    NOTIFICATION_CLASS: ClassVar[bool] = False
    INTERNAL_CLASS: ClassVar[bool] = False
    CONFIRMED_CLASS: ClassVar[bool] = False

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

        if self.nonRepeaters > len(self.variableBindings):
            errmsg = f"The nonRepeaters parameter ({self.nonRepeaters})" \
                " must not exceed the number of variable bindings" \
                f" in the request ({len(self.variableBindings)})"
            raise ValueError(errmsg)

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
            arguments.append(f"requestID={self.requestID}")

        if self.nonRepeaters:
            arguments.append(f"nonRepeaters={self.nonRepeaters}")

        if self.maxRepetitions:
            arguments.append(f"maxRepetitions={self.maxRepetitions}")

        arguments.append(f"variableBindings={self.variableBindings!r}")

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

    def withRequestID(self: TPDU, requestID: int) -> TPDU:
        return self.__class__(
            requestID=requestID,
            nonRepeaters=self.nonRepeaters,
            maxRepetitions=self.maxRepetitions,
            variableBindings=self.variableBindings,
        )

    @classmethod
    def deserialize(cls: Type[TBulkPDU], data: Asn1Data) -> TBulkPDU:
        requestID, nrdata = Integer.decode(data)
        nonRepeaters, mrdata = Integer.decode(nrdata)
        maxRepetitions, vbdata = Integer.decode(mrdata)
        variableBindings = VarBindList.decodeExact(vbdata)

        if nonRepeaters.value < 0:
            msg = "nonRepeaters may not be less than 0"
            raise ParseError(msg, nrdata, mrdata)
        elif maxRepetitions.value < 0:
            msg = "maxRepetitions may not be less than 0"
            raise ParseError(msg, mrdata, vbdata)

        return cls(
            requestID=requestID.value,
            nonRepeaters=nonRepeaters.value,
            maxRepetitions=maxRepetitions.value,
            variableBindings=variableBindings,
        )

@final
class GetRequestPDU(PDU):
    CONFIRMED_CLASS = True
    READ_CLASS = True
    TAG = Tag(0, True, Tag.Class.CONTEXT_SPECIFIC)

    def validResponse(self, vblist):
        if len(vblist) != len(self.variableBindings):
            return False

        for request_vb, response_vb in zip(self.variableBindings, vblist):
            if response_vb.name != request_vb.name:
                return False

        return True

@final
class GetNextRequestPDU(PDU):
    CONFIRMED_CLASS = True
    READ_CLASS = True
    TAG = Tag(1, True, Tag.Class.CONTEXT_SPECIFIC)

    def validResponse(self, vblist):
        if len(vblist) != len(self.variableBindings):
            return False

        for request_vb, response_vb in zip(self.variableBindings, vblist):
            if response_vb.name < request_vb.name:
                return False
            elif (response_vb.name == request_vb.name
            and response_vb.value != EndOfMibView()):
                return False

        return True

@final
class ResponsePDU(PDU):
    RESPONSE_CLASS = True
    TAG = Tag(2, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class SetRequestPDU(PDU):
    CONFIRMED_CLASS = True
    WRITE_CLASS = True
    TAG = Tag(3, True, Tag.Class.CONTEXT_SPECIFIC)

    def validResponse(self, vblist):
        if len(vblist) != len(self.variableBindings):
            return False

        for request_vb, response_vb in zip(self.variableBindings, vblist):
            if response_vb.name != request_vb.name:
                return False

        return True

@final
class GetBulkRequestPDU(BulkPDU):
    CONFIRMED_CLASS = True
    READ_CLASS = True
    TAG = Tag(5, True, Tag.Class.CONTEXT_SPECIFIC)

    def validResponse(self, vblist):
        if len(vblist) < self.nonRepeaters:
            return False

        for i in range(self.nonRepeaters):
            request_vb = self.variableBindings[i]
            response_vb = vblist[i]

            if response_vb.name < request_vb.name:
                return False
            elif (response_vb.name == request_vb.name
            and response_vb.value != EndOfMibView()):
                return False

        repeaters = self.variableBindings[self.nonRepeaters:]
        m = len(repeaters)

        if m > 0:
            repetitions, leftovers = divmod(len(vblist) - self.nonRepeaters, m)

            if repetitions < min(self.maxRepetitions, 1):
                return False
            elif repetitions > self.maxRepetitions:
                return False
            elif leftovers != 0:
                return False

            prev = repeaters
            for r in range(repetitions):
                start = r * m + self.nonRepeaters
                stop = start + m
                successor = vblist[start:stop]

                for i in range(m):
                    request_vb = prev[i]
                    response_vb = successor[i]

                    if response_vb.name < request_vb.name:
                        return False
                    elif (response_vb.name == request_vb.name
                    and response_vb.value != EndOfMibView()):
                        return False

                prev = successor

        return True

@final
class InformRequestPDU(PDU):
    CONFIRMED_CLASS = True
    NOTIFICATION_CLASS = True
    TAG = Tag(6, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class SNMPv2TrapPDU(PDU):
    NOTIFICATION_CLASS = True
    TAG = Tag(7, True, Tag.Class.CONTEXT_SPECIFIC)

@final
class ReportPDU(PDU):
    INTERNAL_CLASS = True
    RESPONSE_CLASS = True
    TAG = Tag(8, True, Tag.Class.CONTEXT_SPECIFIC)

class ErrorResponse(SNMPException):
    def __init__(self,
        status: ErrorStatus,
        index: int,
        request: "AnyPDU",
    ) -> None:
        self.status = status
        self.cause: Union[AnyPDU, OID, int]

        details = ""
        if index == 0:
            self.cause = request
        else:
            try:
                self.cause = request.variableBindings[index-1].name
            except IndexError:
                self.cause = index
            else:
                details = f": {self.cause}"

        super().__init__(f"{status.name}{details}")
