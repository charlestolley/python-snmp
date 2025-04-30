__all__ = ["CredentialsTest", "LocalizedCredentialsTest"]

import unittest

from snmp.security.levels import *
from snmp.security.usm.credentials import *

from . import DummyAuthProtocol, DummyPrivProtocol

class CredentialsTest(unittest.TestCase):
    def setUp(self):
        self.engineID = b"One Ring to rule them all"
        self.authSecret = b"Is it safe?"
        self.privSecret = b"Is it secret?"
        self.secret = self.privSecret + b" " + self.authSecret

    def test_maxSecurityLevel_with_no_authProtocol_is_noAuthNoPriv(self):
        credentials = Credentials()
        self.assertEqual(credentials.maxSecurityLevel, noAuthNoPriv)

    def test_maxSecurityLevel_with_authProtocol_only_is_authNoPriv(self):
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        self.assertEqual(credentials.maxSecurityLevel, authNoPriv)

    def test_maxSecurityLevel_with_privProtocol_is_authPriv(self):
        credentials = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        self.assertEqual(credentials.maxSecurityLevel, authPriv)

    def test_empty_Credentials_produces_empty_LocalizedCredentials(self):
        localizedCredentials = Credentials().localize(self.engineID)
        self.assertIsNone(localizedCredentials.auth)
        self.assertIsNone(localizedCredentials.priv)

    def test_localize_produces_the_expected_keys(self):
        credentials = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        localizedCredentials = credentials.localize(self.engineID)

        self.assertEqual(
            localizedCredentials.auth.key,
            DummyAuthProtocol.localize(self.authSecret, self.engineID),
        )

        self.assertEqual(
            localizedCredentials.priv.key,
            DummyAuthProtocol.localize(self.privSecret, self.engineID),
        )

    def test_secret_is_used_when_privSecret_is_not_given(self):
        credentials = AuthPrivCredentials(
            authProtocol=DummyAuthProtocol,
            privProtocol=DummyPrivProtocol,
            secret=self.secret,
        )

        localizedCredentials = credentials.localize(self.engineID)

        self.assertEqual(
            localizedCredentials.priv.key,
            DummyAuthProtocol.localize(self.secret, self.engineID),
        )

class LocalizedCredentialsTest(unittest.TestCase):
    def test_two_objects_with_equal_auth_and_priv_are_equal(self):
        a = LocalizedCredentials(193, "beef")
        b = LocalizedCredentials(193, "beef")
        self.assertEqual(a, b)

    def test_two_different_objects_are_not_equal(self):
        a = LocalizedCredentials(193, "beef")
        b = LocalizedCredentials(192, "beef")
        c = LocalizedCredentials(193, "beer")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)

if __name__ == "__main__":
    unittest.main()
