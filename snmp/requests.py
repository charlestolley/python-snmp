__all__ = ["ImproperResponse", "RequestIDAuthority", "Timeout"]

from snmp.exception import *
from snmp.numbers import *

class ImproperResponse(SNMPException):
    def __init__(self, variableBindings):
        self.variableBindings = variableBindings

class Timeout(SNMPException):
    pass

class RequestIDAuthority(NumberAuthority):
    class RequestIDAllocationFailure(SNMPLibraryBug):
        # This error is an SNMPLibraryBug type because it should not be
        # possible to run out of available requestIDs. The generator would
        # have had to pass through the full range of requestIDs, and remain
        # so densely full that a new generator could not find an opening. If
        # everything was working properly, there would have to be over a
        # billion outstanding requests in order to ever see this error. On
        # it's own, having a billion outstanding requests would seem to
        # indicate a bug, and, more importantly, encountering this error by
        # any other way would also indicate a bug, so that's why it's a type
        # of SNMPLibraryBug.
        def __init__(self, attempts):
            errmsg = f"No available request ID found after {attempts} attempts"
            super().__init__(errmsg)

            super().__init__(errmsg)

    class RequestIDDeallocationFailure(SNMPLibraryBug):
        def __init__(self, requestID: int):
            errmsg = f"Failed to release request ID {requestID}" \
                " because it is not currently reserved"
            super().__init__(errmsg)

    AllocationFailure = RequestIDAllocationFailure
    DeallocationFailure = RequestIDDeallocationFailure

    @staticmethod
    def newGenerator() -> NumberGenerator:
        return NumberGenerator(32, signed=True)
