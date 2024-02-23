__all__ = ["SecurityLevelTest", "SecurityModelTest"]

import unittest
from snmp.security import *

class SecurityLevelTest(unittest.TestCase):
    def setUp(self):
        self.noAuthNoPriv = SecurityLevel()
        self.authNoPriv = SecurityLevel(auth=True)
        self.authPriv = SecurityLevel(auth=True, priv=True)

    def test_constructor_raises_ValueError_for_priv_without_auth(self):
        self.assertRaises(ValueError, SecurityLevel, priv=True)

    def test_different_levels_are_not_equal(self):
        self.assertNotEqual(self.noAuthNoPriv, self.authNoPriv)
        self.assertNotEqual(self.noAuthNoPriv, self.authPriv)
        self.assertNotEqual(self.authNoPriv, self.authPriv)

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        self.assertEqual(eval(repr(self.noAuthNoPriv)), self.noAuthNoPriv)
        self.assertEqual(eval(repr(self.authNoPriv)), self.authNoPriv)
        self.assertEqual(eval(repr(self.authPriv)), self.authPriv)

    def test_any_security_level_is_less_than_a_higher_security_level(self):
        self.assertLess(self.noAuthNoPriv, self.authNoPriv)
        self.assertLess(self.noAuthNoPriv, self.authPriv)
        self.assertLess(self.authNoPriv, self.authPriv)

    def test_any_security_level_is_greater_than_a_lower_security_level(self):
        self.assertGreater(self.authNoPriv, self.noAuthNoPriv)
        self.assertGreater(self.authPriv, self.noAuthNoPriv)
        self.assertGreater(self.authPriv, self.authNoPriv)

    def test_auth_and_priv_are_immutable(self):
        errortype = AttributeError
        self.assertRaises(errortype, setattr, self.noAuthNoPriv, "auth", True)
        self.assertRaises(errortype, setattr, self.authNoPriv, "auth", False)
        self.assertRaises(errortype, setattr, self.authNoPriv, "priv", True)
        self.assertRaises(errortype, setattr, self.authPriv, "priv", False)

class SecurityModelTest(unittest.TestCase):
    def test_USM_has_a_value_of_3(self):
        self.assertEqual(SecurityModel.USM, 3)

if __name__ == '__main__':
    unittest.main()
