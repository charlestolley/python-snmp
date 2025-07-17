__all__ = ["SNMPv3ManagerAddUserTest", "SNMPv3ManagerNoAddUserTest"]

import unittest

from snmp.engine import *
from snmp.security.levels import *

from test.security.usm import DummyAuthProtocol

class SNMPv3ManagerNoAddUserTest(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()
        self.addr = "127.0.0.1"
        self.user = "chuck"

    def test_no_addUser_no_defaultUser_raises_TypeError(self):
        self.assertRaises(TypeError, self.engine.Manager, self.addr)

    def test_defaultUser_without_addUser_defaults_to_noAuthNoPriv(self):
        manager = self.engine.Manager(self.addr, defaultUser=self.user)
        self.assertEqual(manager.defaultSecurityLevel, noAuthNoPriv)

    def test_defaultUser_without_addUser_accepts_noAuthNoPriv(self):
        manager = self.engine.Manager(
            self.addr,
            defaultUser=self.user,
            defaultSecurityLevel=noAuthNoPriv,
        )

        self.assertEqual(manager.defaultSecurityLevel, noAuthNoPriv)

    def test_defaultUser_without_addUser_ValueError_for_authNoPriv(self):
        self.assertRaises(
            ValueError,
            self.engine.Manager,
            self.addr,
            defaultUser=self.user,
            defaultSecurityLevel=authNoPriv,
        )

class SNMPv3ManagerAddUserTest(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

        self.addr = "127.0.0.1"
        self.user = "chuck"
        self.otherUser = "other"

        self.engine.addUser(
            self.user,
            authProtocol=DummyAuthProtocol,
            authSecret=b"asdf",
        )

        self.engine.addUser(self.otherUser)

    def test_defaultUser_and_defaultSecurityLevel_inferred_from_addUser(self):
        manager = self.engine.Manager(self.addr)
        self.assertEqual(manager.defaultUserName, self.user.encode())
        self.assertEqual(manager.defaultSecurityLevel, authNoPriv)

    def test_defaultSecurityLevel_inferred_from_defaultUser(self):
        manager = self.engine.Manager(self.addr, defaultUser = self.otherUser)
        self.assertEqual(manager.defaultUserName, self.otherUser.encode())
        self.assertEqual(manager.defaultSecurityLevel, noAuthNoPriv)

    def test_no_defaultUser_ValueError_if_defaultSecurityLevel_too_high(self):
        self.assertRaises(
            ValueError,
            self.engine.Manager,
            self.addr,
            defaultSecurityLevel = authPriv,
        )

    def test_ValueError_if_defaultSecurityLevel_is_too_high(self):
        self.assertRaises(
            ValueError,
            self.engine.Manager,
            self.addr,
            defaultUser = self.otherUser,
            defaultSecurityLevel = authNoPriv,
        )

    def test_a_second_call_to_addUser_overrides_the_first_one(self):
        self.engine.addUser(
            self.otherUser,
            authProtocol=DummyAuthProtocol,
            authSecret=b"fdsa",
        )

        manager = self.engine.Manager(
            self.addr,
            defaultUser = self.otherUser,
            defaultSecurityLevel = authNoPriv,
        )

if __name__ == "__main__":
    unittest.main()
