__all__ = ["NamespaceConfigTest", "UserConfigTest", "UserRegistryTest"]

import unittest

from snmp.security.levels import *
from snmp.security.usm.credentials import *
from snmp.security.usm.users import *
from snmp.security.usm.users import NamespaceConfig, UserConfig

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
        self.user = b"user1"
        self.other = b"user2"
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

class UserRegistryTest(unittest.TestCase):
    def setUp(self):
        self.users = UserRegistry()
        self.userName = b"somebody"
        self.otherName = b"you"
        self.authProtocol = DummyAuthProtocol
        self.privProtocol = DummyPrivProtocol
        self.secret = b"you had a boyfriend who looked like a girlfriend" \
            b" that I had in February of last year"

        self.engineID = b"track 18"
        self.namespace = "songs"

    def test_first_user_added_is_the_default(self):
        self.users.addUser(self.userName)
        self.users.addUser(self.otherName)
        self.assertEqual(self.users.getDefaultUser(), self.userName)

    def test_provided_protocols_dictate_defaultSecurityLevel(self):
        self.users.addUser(
            self.userName,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=self.secret,
        )

        level = self.users.getDefaultSecurityLevel(self.userName)
        self.assertEqual(level, authPriv)

        self.users.addUser(self.otherName)
        level = self.users.getDefaultSecurityLevel(self.otherName)
        self.assertEqual(level, noAuthNoPriv)

    def test_defaultSecurityLevel_overrides_inferred_default(self):
        self.users.addUser(
            self.userName,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=self.secret,
            defaultSecurityLevel=authNoPriv,
        )

        level = self.users.getDefaultSecurityLevel(self.userName)
        self.assertEqual(level, authNoPriv)

    def test_default_overrides_automatic_default_user_selection(self):
        self.users.addUser(self.userName)
        self.users.addUser(self.otherName, default=True)
        self.assertEqual(self.users.getDefaultUser(), self.otherName)

    def test_each_namespace_has_its_own_default_user(self):
        self.users.addUser(self.userName, namespace=self.namespace)
        self.users.addUser(self.otherName)

        userName = self.users.getDefaultUser(self.namespace)
        self.assertEqual(userName, self.userName)
        self.assertEqual(self.users.getDefaultUser(), self.otherName)

    def test_no_error_to_add_the_same_userName_in_two_namespaces(self):
        self.users.addUser(self.userName)
        self.users.addUser(
            self.userName,
            self.authProtocol,
            self.secret,
            namespace=self.namespace,
        )

    def test_getCredentials_finds_the_user_for_the_assigned_namespace(self):
        self.users.addUser(self.userName)
        self.users.addUser(
            self.userName,
            self.authProtocol,
            self.secret,
            namespace=self.namespace,
        )

        self.users.assign(self.engineID, self.namespace)
        user = self.users.getCredentials(self.engineID, self.userName)

        credentials = Credentials(self.authProtocol, self.secret)
        self.assertEqual(user, credentials.localize(self.engineID))
        self.assertNotEqual(user, Credentials().localize(self.engineID))

    def test_its_legal_to_assign_empty_namespace(self):
        self.users.assign(self.engineID, self.namespace)

    def test_what_happens_if_you_reassign_an_engine(self):
        self.users.addUser(self.userName, self.authProtocol, self.secret)
        self.users.addUser(self.otherName)
        self.users.addUser(self.userName, namespace=self.namespace)

        self.users.assign(self.engineID, "")
        self.users.assign(self.engineID, self.namespace)
        user = self.users.getCredentials(self.engineID, self.userName)
        self.assertEqual(user, Credentials().localize(self.engineID))

        self.assertRaises(
            InvalidUserName,
            self.users.getCredentials,
            self.engineID,
            self.otherName,
        )

    def test_get_unknown_credentials(self):
        self.assertRaises(
            InvalidEngineID,
            self.users.getCredentials,
            self.engineID,
            self.userName,
        )

        self.users.assign(self.engineID, self.namespace)
        self.assertRaises(
            InvalidUserName,
            self.users.getCredentials,
            self.engineID,
            self.userName,
        )

if __name__ == "__main__":
    unittest.main()
