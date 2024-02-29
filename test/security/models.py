__all__ = ["SecurityModelTest"]

import unittest

from snmp.security.models import *

class SecurityModelTest(unittest.TestCase):
    def test_USM_has_a_value_of_3(self):
        self.assertEqual(SecurityModel.USM, 3)

if __name__ == '__main__':
    unittest.main()
