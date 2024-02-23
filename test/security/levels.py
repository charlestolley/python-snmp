__all__ = ["SecurityLevelsTest"]

import unittest
from snmp.security.levels import *

class SecurityLevelsTest(unittest.TestCase):
    def test_noAuthNoPriv_auth_is_False_and_priv_is_False(self):
        self.assertFalse(noAuthNoPriv.auth)
        self.assertFalse(noAuthNoPriv.priv)

    def test_authNoPriv_auth_is_True_and_priv_is_False(self):
        self.assertTrue (authNoPriv.auth)
        self.assertFalse(authNoPriv.priv)

    def test_authPriv_auth_is_True_and_priv_is_True(self):
        self.assertTrue(authPriv.auth)
        self.assertTrue(authPriv.priv)

    def test__str__function_returns_the_name(self):
        self.assertEqual(str(noAuthNoPriv), "noAuthNoPriv")
        self.assertEqual(str(authNoPriv), "authNoPriv")
        self.assertEqual(str(authPriv), "authPriv")

if __name__ == '__main__':
    unittest.main()
