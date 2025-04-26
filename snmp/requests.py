__all__ = ["RequestIDAuthority", "Timeout"]

from snmp.exception import *
from snmp.numbers import *

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
        def __init__(self, attempts=None):
            if attempts is None:
                errmsg = "No available request ID was found"
            else:
                errmsg = f"After {attempts} attempts," \
                " no available request ID was found"

            super().__init__(errmsg)

    class RequestIDDeallocationFailure(SNMPLibraryBug):
        pass

    AllocationFailure = RequestIDAllocationFailure
    DeallocationFailure = RequestIDDeallocationFailure

    @staticmethod
    def newGenerator() -> NumberGenerator:
        return NumberGenerator(32, signed=True)
