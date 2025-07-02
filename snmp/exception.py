__all__ = [
    "SNMPException",
    "SNMPLibraryBug",
    "IncomingMessageError",
    "IncomingMessageErrorWithPointer",
]

from os import linesep

from snmp.typing import Optional, Union
from snmp.utils import subbytes

class SNMPException(Exception):
    """Base class for all run-time exceptions in this library."""

class SNMPLibraryBug(AssertionError):
    """Base class for logic errors in the code of this library."""

class IncomingMessageError(SNMPException):
    """An error indicating a received message is invalid in some way."""

class IncomingMessageErrorWithPointer(IncomingMessageError):
    def __init__(self,
        msg: str,
        data: Union[bytes, subbytes],
        tail: Optional[subbytes] = None,
    ) -> None:
        super().__init__(msg)

        if tail is None:
            self.data = subbytes(data)
        else:
            self.data = subbytes(data, stop=len(data) - len(tail))

    def __str__(self):
        return f"{super().__str__()}{linesep}{self.data}"
