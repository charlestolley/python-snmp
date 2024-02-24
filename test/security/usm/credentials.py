__all__ = []

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
        credentials = Credentials(DummyAuthProtocol, self.authSecret)
        self.assertEqual(credentials.maxSecurityLevel, authNoPriv)

    def test_maxSecurityLevel_with_privProtocol_is_authPriv(self):
        credentials = Credentials(
            DummyAuthProtocol,
            self.authSecret,
            DummyPrivProtocol,
            self.privSecret,
        )

        self.assertEqual(credentials.maxSecurityLevel, authPriv)

    def test_empty_Credentials_produces_empty_LocalizedCredentials(self):
        localizedCredentials = Credentials().localize(self.engineID)
        self.assertIsNone(localizedCredentials.auth)
        self.assertIsNone(localizedCredentials.priv)

    def test_localize_produces_the_expected_keys(self):
        credentials = Credentials(
            DummyAuthProtocol,
            self.authSecret,
            DummyPrivProtocol,
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

    def test_secret_is_used_when_authSecret_is_not_given(self):
        credentials = Credentials(
            authProtocol=DummyAuthProtocol,
            secret=self.secret,
        )

        localizedCredentials = credentials.localize(self.engineID)

        self.assertEqual(
            localizedCredentials.auth.key,
            DummyAuthProtocol.localize(self.secret, self.engineID),
        )

    def test_secret_is_used_when_privSecret_is_not_given(self):
        credentials = Credentials(
            authProtocol=DummyAuthProtocol,
            privProtocol=DummyPrivProtocol,
            secret=self.secret,
        )

        localizedCredentials = credentials.localize(self.engineID)

        self.assertEqual(
            localizedCredentials.priv.key,
            DummyAuthProtocol.localize(self.secret, self.engineID),
        )

if __name__ == "__main__":
    unittest.main()
