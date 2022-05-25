__all__ = ["SecurityLevelTest", "SecurityModelTest"]

import unittest
from snmp.security import *

class SecurityLevelTest(unittest.TestCase):
    def setUp(self):
        self.noAuthNoPriv = SecurityLevel()
        self.authNoPriv = SecurityLevel(auth=True)
        self.authPriv = SecurityLevel(auth=True, priv=True)

    def setAuth(self, obj, value):
        obj.auth = value

    def setPriv(self, obj, value):
        obj.priv = value

    def testConstructor(self):
        self.assertRaises(ValueError, SecurityLevel, priv=True)

    def testRepr(self):
        self.assertEqual(eval(repr(self.noAuthNoPriv)), self.noAuthNoPriv)
        self.assertEqual(eval(repr(self.authNoPriv)), self.authNoPriv)
        self.assertEqual(eval(repr(self.authPriv)), self.authPriv)

    def testStr(self):
        self.assertEqual(str(self.noAuthNoPriv), "noAuthNoPriv")
        self.assertEqual(str(self.authNoPriv), "authNoPriv")
        self.assertEqual(str(self.authPriv), "authPriv")

    def testNotEqual(self):
        self.assertNotEqual(self.noAuthNoPriv, self.authNoPriv)
        self.assertNotEqual(self.noAuthNoPriv, self.authPriv)
        self.assertNotEqual(self.authNoPriv, self.authPriv)

    def testLess(self):
        self.assertLess(self.noAuthNoPriv, self.authNoPriv)
        self.assertLess(self.noAuthNoPriv, self.authPriv)
        self.assertLess(self.authNoPriv, self.authPriv)

    def testSetAuth(self):
        self.noAuthNoPriv.auth = True
        self.assertEqual(self.noAuthNoPriv, self.authNoPriv)

    def testUnsetAuth(self):
        self.authNoPriv.auth = False
        self.assertEqual(self.authNoPriv, self.noAuthNoPriv)

    def testInvalidAuth(self):
        self.assertRaises(ValueError, self.setAuth, self.authPriv, False)

    def testSetPriv(self):
        self.authNoPriv.priv = True
        self.assertEqual(self.authNoPriv, self.authPriv)

    def testUnsetPriv(self):
        self.authPriv.priv = False
        self.assertEqual(self.authPriv, self.authNoPriv)

    def testInvalidPriv(self):
        self.assertRaises(ValueError, self.setPriv, self.noAuthNoPriv, True)

class SecurityModelTest(unittest.TestCase):
    def testUSM(self):
        self.assertEqual(SecurityModel.USM, 3)

if __name__ == '__main__':
    unittest.main()
