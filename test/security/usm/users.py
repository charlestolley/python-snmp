__all__ = ["UserRegistryTest"]

import unittest

from snmp.security.levels import *
from snmp.security.usm.credentials import *
from snmp.security.usm.users import *

from . import DummyAuthProtocol, DummyPrivProtocol

class UserRegistryTest(unittest.TestCase):
    def setUp(self):
        self.userName = b"somebody"
        self.otherName = b"you"
        self.authProtocol = DummyAuthProtocol
        self.privProtocol = DummyPrivProtocol
        self.secret = b"you had a boyfriend who looked like a girlfriend" \
            b" that I had in February of last year"
        self.authSecret = b"not confidential"
        self.privSecret = b"I got potential"

        self.engineID = b"track 18"
        self.namespace = "songs"
        self.users = UserRegistry()

    def test_addUser_ValueError_for_empty_userName(self):
        self.assertRaises(ValueError, self.users.addUser, b"", self.namespace)

    def test_addUser_accepts_32_character_userName(self):
        self.users.addUser(b"abcdefghijklmnopqrstuvwxyz123456", self.namespace)

    def test_addUser_ValueError_for_33_character_userName(self):
        self.assertRaises(
            ValueError,
            self.users.addUser,
            b"abcdefghijklmnopqrstuvwxyz1234567",
            self.namespace,
        )

    def test_addUser_accepts_the_same_userName_in_different_namespaces(self):
        self.users.addUser(self.userName, self.namespace)
        self.users.addUser(self.userName, "a different namespace")

    def test_first_user_added_is_the_default(self):
        self.users.addUser(self.userName, self.namespace)
        self.users.addUser(self.otherName, self.namespace)
        self.assertEqual(
            self.users.defaultUserName(self.namespace),
            self.userName,
        )

    def test_first_user_added_to_namespace_ValueError_if_default_False(self):
        self.assertRaises(
            ValueError,
            self.users.addUser,
            self.userName,
            self.namespace,
            default=False,
        )

        self.users.addUser(self.userName, self.namespace)

        self.assertRaises(
            ValueError,
            self.users.addUser,
            self.userName,
            "a different namespace",
            default=False,
        )

    def test_addUser_override_default_user_with_default_True(self):
        self.users.addUser(self.userName, self.namespace)
        self.users.addUser(self.otherName, self.namespace, default=True)

        defaultUserName = self.users.defaultUserName(self.namespace)
        self.assertEqual(defaultUserName, self.otherName)

    def test_each_namespace_has_its_own_default_user(self):
        otherNamespace = "not your namespace"
        self.users.addUser(self.userName, self.namespace)
        self.users.addUser(self.otherName, self.namespace)
        self.users.addUser(self.otherName, otherNamespace)
        self.users.addUser(self.userName, otherNamespace)

        self.assertEqual(
            self.users.defaultUserName(self.namespace),
            self.userName,
        )

        self.assertEqual(
            self.users.defaultUserName(otherNamespace),
            self.otherName,
        )

    def test_TypeError_for_invalid_credentials_arguments(self):
        ap = self.authProtocol
        a = self.authSecret
        pp = self.privProtocol
        p = self.privSecret
        s = self.secret

        permutations = [
            ((None, None, None, None, None),  True),
            ((None, None, None, None,    s), False),
            ((None, None, None,    p, None), False),
            ((None, None, None,    p,    s), False),
            ((None, None,   pp, None, None), False),
            ((None, None,   pp, None,    s), False),
            ((None, None,   pp,    p, None), False),
            ((None, None,   pp,    p,    s), False),
            ((None,    a, None, None, None), False),
            ((None,    a, None, None,    s), False),
            ((None,    a, None,    p, None), False),
            ((None,    a, None,    p,    s), False),
            ((None,    a,   pp, None, None), False),
            ((None,    a,   pp, None,    s), False),
            ((None,    a,   pp,    p, None), False),
            ((None,    a,   pp,    p,    s), False),
            ((  ap, None, None, None, None), False),
            ((  ap, None, None, None,    s),  True),
            ((  ap, None, None,    p, None), False),
            ((  ap, None, None,    p,    s), False),
            ((  ap, None,   pp, None, None), False),
            ((  ap, None,   pp, None,    s),  True),
            ((  ap, None,   pp,    p, None), False),
            ((  ap, None,   pp,    p,    s), False),
            ((  ap,    a, None, None, None),  True),
            ((  ap,    a, None, None,    s), False),
            ((  ap,    a, None,    p, None), False),
            ((  ap,    a, None,    p,    s), False),
            ((  ap,    a,   pp, None, None), False),
            ((  ap,    a,   pp, None,    s), False),
            ((  ap,    a,   pp,    p, None),  True),
            ((  ap,    a,   pp,    p,    s), False),
        ]

        for args, valid in permutations:
            users = UserRegistry()
            authProtocol, authSecret, privProtocol, privSecret, secret = args

            if valid:
                users.addUser(
                    self.userName,
                    self.namespace,
                    authProtocol=authProtocol,
                    authSecret=authSecret,
                    privProtocol=privProtocol,
                    privSecret=privSecret,
                    secret=secret,
                )
            else:
                self.assertRaises(
                    TypeError,
                    users.addUser,
                    self.userName,
                    self.namespace,
                    authProtocol=authProtocol,
                    authSecret=authSecret,
                    privProtocol=privProtocol,
                    privSecret=privSecret,
                    secret=secret,
                )

    def test_provided_protocols_dictate_defaultSecurityLevel(self):
        self.users.addUser(
            self.userName,
            self.namespace,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=self.secret,
        )

        level = self.users.defaultSecurityLevel(self.userName, self.namespace)
        self.assertEqual(level, authPriv)

        self.users.addUser(
            self.otherName,
            self.namespace,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        level = self.users.defaultSecurityLevel(self.otherName, self.namespace)
        self.assertEqual(level, authNoPriv)

        self.users.addUser(self.userName, "")
        level = self.users.defaultSecurityLevel(self.userName, "")
        self.assertEqual(level, noAuthNoPriv)

    def test_defaultSecurityLevel_overrides_inferred_default(self):
        self.users.addUser(
            self.userName,
            self.namespace,
            authProtocol=self.authProtocol,
            privProtocol=self.privProtocol,
            secret=self.secret,
            defaultSecurityLevel=authNoPriv,
        )

        level = self.users.defaultSecurityLevel(self.userName, self.namespace)
        self.assertEqual(level, authNoPriv)

    def test_addUser_raises_ValueError_if_defaultSecurityLevel_too_high(self):
        self.assertRaises(
            ValueError,
            self.users.addUser,
            self.userName,
            self.namespace,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
            defaultSecurityLevel=authPriv,
        )

        self.assertRaises(
            ValueError,
            self.users.addUser,
            self.otherName,
            self.namespace,
            defaultSecurityLevel=authNoPriv,
        )

    def test_namespaces_list_all_namespaces_containing_a_username(self):
        self.users.addUser(self.userName, self.namespace)
        self.users.addUser(self.userName, "included namespace")
        self.users.addUser(self.otherName, "excluded namespace")

        namespaces = set(self.users.namespaces(self.userName))
        self.assertEqual(len(namespaces), 2)
        self.assertIn(self.namespace, namespaces)
        self.assertIn("included namespace", namespaces)

    def test_exists_returns_True_if_a_user_is_defined_in_a_namespace(self):
        self.users.addUser(
            self.userName,
            self.namespace,
        )

        self.assertTrue(self.users.exists(self.userName, self.namespace))

    def test_exists_returns_False_if_user_is_not_defined_in_namespace(self):
        self.assertFalse(self.users.exists(self.userName, self.namespace))

    def test_credentials_produces_the_right_localized_credentials(self):
        self.users.addUser(
            self.userName,
            self.namespace,
            authProtocol=self.authProtocol,
            authSecret=self.authSecret,
        )

        credentials = AuthCredentials(self.authProtocol, self.authSecret)
        wrongCredentials = AuthCredentials(self.authProtocol, self.secret)
        localizedCredentials = credentials.localize(self.engineID)
        wrongLocalizedCredentials = wrongCredentials.localize(self.engineID)

        result = self.users.credentials(
            self.userName,
            self.namespace,
            self.engineID,
        )

        self.assertEqual(result, localizedCredentials)
        self.assertNotEqual(result, wrongLocalizedCredentials)

    def test_credentials_raises_ValueError_for_unknown_user(self):
        self.assertRaises(
            ValueError,
            self.users.credentials,
            self.userName,
            self.namespace,
            self.engineID,
        )

if __name__ == "__main__":
    unittest.main()
