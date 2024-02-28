__all__ = ["NamespaceConfigTest", "UserConfigTest"]

import unittest

from snmp.security.levels import *
from snmp.security.usm.credentials import *
from snmp.security.usm.users import *
from snmp.security.usm.users import UserConfig

from . import DummyAuthProtocol, DummyPrivProtocol

class UserConfigTest(unittest.TestCase):
    def setUp(self):
        self.credentials = Credentials(
            authProtocol=DummyAuthProtocol,
            privProtocol=DummyPrivProtocol,
            secret=b"keep it quiet",
        )

    def test_raise_ValueError_if_defaultSecurityLevel_is_too_high(self):
        noauth = Credentials()
        nopriv = Credentials(DummyAuthProtocol, b"shh, it's a secret")
        self.assertRaises(ValueError, UserConfig, noauth, authNoPriv)
        self.assertRaises(ValueError, UserConfig, nopriv, authPriv)

    def test_two_identical_configs_are_equal(self):
        self.assertEqual(
            UserConfig(self.credentials),
            UserConfig(self.credentials),
        )

    def test_two_different_configs_are_different(self):
        self.assertNotEqual(
            UserConfig(self.credentials, authPriv),
            UserConfig(self.credentials, authNoPriv),
        )

        self.assertNotEqual(
            UserConfig(self.credentials),
            UserConfig(Credentials()),
        )

class NamespaceConfigTest(unittest.TestCase):
    def setUp(self):
        self.user = "user1"
        self.other = "user2"
        self.userCreds = Credentials(DummyAuthProtocol, b"secret")
        self.otherCreds = Credentials(DummyAuthProtocol, b"other")
        self.config = NamespaceConfig()

    def test_first_added_user_is_the_default(self):
        self.config.addUser(self.user, self.userCreds)
        self.config.addUser(self.other, self.otherCreds)
        self.assertEqual(self.config.defaultUserName, self.user)

    def test_default_parameter_overrides_first_added_user(self):
        self.config.addUser(self.user, self.userCreds)
        self.config.addUser(self.other, self.userCreds, default=True)
        self.assertEqual(self.config.defaultUserName, self.other)

    def test_adding_the_same_userName_twice_raises_UserNameCollision(self):
        self.config.addUser(self.user, self.userCreds)

        self.assertRaises(
            UserNameCollision,
            self.config.addUser,
            self.user,
            self.otherCreds,
        )

    def test_addUser_twice_with_the_same_config_does_nothing(self):
        self.config.addUser(self.user, self.userCreds)
        self.config.addUser(self.user, self.userCreds)

    def test_addUser_twice_changing_default_raises_UserNameCollision(self):
        self.config.addUser(self.user, self.userCreds)
        self.config.addUser(self.other, self.otherCreds)

        self.assertRaises(
            UserNameCollision,
            self.config.addUser,
            self.other,
            self.otherCreds,
            default=True,
        )

    def test_addUser_twice_reiterating_default_does_nothing(self):
        self.config.addUser(self.user, self.userCreds)
        self.config.addUser(self.other, self.otherCreds)
        self.config.addUser(self.user, self.userCreds, default=True)

    def test_findUser_returns_the_correct_UserConfig(self):
        userArgs = (self.userCreds, noAuthNoPriv)
        otherArgs = (self.otherCreds, authNoPriv)
        userConfig = UserConfig(*userArgs)
        otherConfig = UserConfig(*otherArgs)

        self.config.addUser(self.user, *userArgs)
        self.config.addUser(self.other, *otherArgs)
        self.assertEqual(self.config.findUser(self.user), userConfig)
        self.assertNotEqual(self.config.findUser(self.user), otherConfig)

    def test_findUser_raises_InvalidUserName_for_invalid_userName(self):
        self.assertRaises(
            InvalidUserName,
            self.config.findUser,
            self.user,
        )

    def test_iterator_yields_all_userNames_and_UserConfigs(self):
        expected = list(sorted((
            (self.user, UserConfig(self.userCreds)),
            (self.other, UserConfig(self.otherCreds)),
        )))

        self.config.addUser(self.user, self.userCreds)
        self.config.addUser(self.other, self.otherCreds)
        self.assertEqual(list(sorted(iter(self.config))), expected)

if __name__ == "__main__":
    unittest.main()
