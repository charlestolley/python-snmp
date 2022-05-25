__all__ = ["SecurityLevelsTest"]

import unittest
from snmp.security.levels import *

class SecurityLevelsTest(unittest.TestCase):
    def testNoAuthNoPriv(self):
        self.assertFalse(noAuthNoPriv.auth)
        self.assertFalse(noAuthNoPriv.priv)

    def testAuthNoPriv(self):
        self.assertTrue (authNoPriv.auth)
        self.assertFalse(authNoPriv.priv)

    def testAuthPriv(self):
        self.assertTrue(authPriv.auth)
        self.assertTrue(authPriv.priv)

    def testStr(self):
        self.assertEqual(str(noAuthNoPriv), "noAuthNoPriv")
        self.assertEqual(str(authNoPriv), "authNoPriv")
        self.assertEqual(str(authPriv), "authPriv")

if __name__ == '__main__':
    unittest.main()
