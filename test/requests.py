__all__ = ["RequestIDAuthorityTest"]

import unittest

from snmp.exception import *
from snmp.numbers import *
from snmp.requests import *

class RequestIDAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.authority = RequestIDAuthority()

    def test_RequestIDAuthority_inherits_from_NumberAuthority(self):
        self.assertIsInstance(self.authority, NumberAuthority)

    def test_reserve_returns_unique_nonzero_32_bit_signed_requestID(self):
        requestIDs = set()

        for _ in range(1000):
            requestID = self.authority.reserve()
            requestIDs.add(requestID)

            self.assertGreaterEqual(requestID, -(1 << 31))
            self.assertLess(requestID, 1 << 31)
            self.assertNotEqual(requestID, 0)

        self.assertEqual(len(requestIDs), 1000)

    def test_AllocationFailure_is_an_SNMPLibraryBug(self):
        exception = self.authority.AllocationFailure()
        self.assertIsInstance(exception, SNMPLibraryBug)

    def test_DeallocationFailure_is_an_SNMPLibraryBug(self):
        exception = self.authority.DeallocationFailure()
        self.assertIsInstance(exception, SNMPLibraryBug)

if __name__ == "__main__":
    unittest.main()
