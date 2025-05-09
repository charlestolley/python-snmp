__all__ = ["CredentialsTest"]

import unittest

from snmp.exception import *
from snmp.smi import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm.credentials import *
from snmp.security.usm.parameters import *
from snmp.utils import *
from snmp.v3.message import *

from . import DummyAuthProtocol, DummyPrivProtocol

class CredentialsTest(unittest.TestCase):
    def setUp(self):
        self.engineID = b"One Ring to rule them all"
        self.authSecret = b"Is it safe?"
        self.privSecret = b"Is it secret?"
        self.secret = self.privSecret + b" " + self.authSecret

        self.authHeader = HeaderData(
            0x18273645,
            484,
            MessageFlags(authNoPriv, reportable=True),
            SecurityModel.USM,
        )

        self.authPrivHeader = HeaderData(
            0x12345678,
            484,
            MessageFlags(authPriv, reportable=True),
            SecurityModel.USM,
        )

        self.scopedPDU = ScopedPDU(
            GetRequestPDU("1.2.3.4.5.6"),
            self.engineID,
        )

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

    def test_TypeError_for_missing_authSecret(self):
        self.assertRaises(TypeError, AuthCredentials, DummyAuthProtocol)

    def test_TypeError_for_missing_secrets(self):
        self.assertRaises(
            TypeError,
            AuthPrivCredentials,
            DummyAuthProtocol,
            DummyPrivProtocol,
        )

        self.assertRaises(
            TypeError,
            AuthPrivCredentials,
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
        )

        self.assertRaises(
            TypeError,
            AuthPrivCredentials,
            DummyAuthProtocol,
            DummyPrivProtocol,
            privSecret=self.privSecret,
        )

    def test_TypeError_for_multiple_secrets(self):
        self.assertRaises(
            TypeError,
            AuthPrivCredentials,
            DummyAuthProtocol,
            DummyPrivProtocol,
            secret=self.secret,
            authSecret=self.authSecret,
        )

        self.assertRaises(
            TypeError,
            AuthPrivCredentials,
            DummyAuthProtocol,
            DummyPrivProtocol,
            secret=self.secret,
            privSecret=self.privSecret,
        )

    def test_empty_lc_equal_to_each_other(self):
        credentials = Credentials()
        l1 = credentials.localize(self.engineID)
        l2 = credentials.localize(b"different engineID")
        self.assertEqual(l1, l2)

    def test_auth_lc_with_different_engineIDs_are_not_equal(self):
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        l1 = credentials.localize(self.engineID)
        l2 = credentials.localize(b"different engineID")
        self.assertNotEqual(l1, l2)

    def test_auth_lc_with_different_credentials_are_not(self):
        c1 = AuthCredentials(DummyAuthProtocol, self.authSecret)
        c2 = AuthCredentials(DummyAuthProtocol, self.privSecret)
        l1 = c1.localize(self.engineID)
        l2 = c2.localize(self.engineID)
        self.assertNotEqual(l1, l2)

    def test_auth_lc_with_the_same_credentials_and_engineID_are_equal(self):
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        l1 = credentials.localize(self.engineID)
        l2 = credentials.localize(self.engineID)
        self.assertEqual(l1, l2)

    def test_priv_lc_with_different_engineIDs_are_not_equal(self):
        credentials = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        l1 = credentials.localize(self.engineID)
        l2 = credentials.localize(b"different engineID")
        self.assertNotEqual(l1, l2)

    def test_priv_lc_with_different_auth_credentials_are_not_equal(self):
        c1 = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        c2 = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            secret=self.secret,
        )

        l1 = c1.localize(self.engineID)
        l2 = c2.localize(self.engineID)
        self.assertNotEqual(l1, l2)

    def test_priv_lc_with_different_priv_credentials_are_not_equal(self):
        c1 = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.secret,
            self.privSecret,
        )

        c2 = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            secret=self.secret,
        )

        l1 = c1.localize(self.engineID)
        l2 = c2.localize(self.engineID)
        self.assertNotEqual(l1, l2)

    def test_priv_lc_with_the_same_credentials_and_engineID_are_equal(self):
        c1 = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        c2 = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        l1 = c1.localize(self.engineID)
        l2 = c2.localize(self.engineID)
        self.assertEqual(l1, l2)

    def test_priv_lc_not_equal_to_auth_only_lc(self):
        c1 = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        c2 = AuthCredentials(DummyAuthProtocol, self.authSecret)

        l1 = c1.localize(self.engineID)
        l2 = c2.localize(self.engineID)
        self.assertNotEqual(l1, l2)

    def test_empty_lc_withoutPrivacy_equals_self(self):
        credentials = Credentials()
        localizedCredentials = credentials.localize(self.engineID)

        self.assertEqual(
            localizedCredentials.withoutPrivacy(),
            localizedCredentials,
        )

    def test_auth_lc_withoutPrivacy_equals_self(self):
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        localizedCredentials = credentials.localize(self.engineID)

        self.assertEqual(
            localizedCredentials.withoutPrivacy(),
            localizedCredentials,
        )

    def test_priv_lc_withoutPrivacy_equals_auth_lc(self):
        auth = AuthCredentials(DummyAuthProtocol, self.authSecret)

        priv = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        l1 = auth.localize(self.engineID)
        l2 = priv.localize(self.engineID)

        self.assertNotEqual(l1, l2)
        self.assertEqual(l1, l2.withoutPrivacy())

    def test_empty_lc_signaturePlaceholder_AuthenticationNotEnabled(self):
        credentials = Credentials()
        localizedCredentials = credentials.localize(self.engineID)

        self.assertRaises(
            AuthenticationNotEnabled,
            localizedCredentials.signaturePlaceholder,
        )

    def test_auth_lc_signaturePlaceholder_is_one_or_more_zero_bytes(self):
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        localizedCredentials = credentials.localize(self.engineID)

        padding = localizedCredentials.signaturePlaceholder()
        self.assertGreater(len(padding), 0)
        self.assertFalse(any(padding))

    def test_priv_lc_signaturePlaceholder_is_one_or_more_zero_bytes(self):
        credentials = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        localizedCredentials = credentials.localize(self.engineID)

        padding = localizedCredentials.signaturePlaceholder()
        self.assertGreater(len(padding), 0)
        self.assertFalse(any(padding))

    def test_empty_lc_sign_raises_AuthenticationNotEnabled(self):
        credentials = Credentials()
        localizedCredentials = credentials.localize(self.engineID)

        securityParameters = UnsignedUsmParameters(
            self.engineID,
            262,
            263,
            b"noAuthUser",
            b"",
            b"",
        )

        message = SNMPv3WireMessage(
            self.authHeader,
            self.scopedPDU,
            OctetString(securityParameters.encode()),
        )

        self.assertRaises(
            AuthenticationNotEnabled,
            localizedCredentials.sign,
            message,
        )

    def test_auth_lc_sign_returns_encoded_SNMPv3WireMessage(self):
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        localizedCredentials = credentials.localize(self.engineID)

        securityParameters = UnsignedUsmParameters(
            self.engineID,
            295,
            296,
            b"authUser",
            localizedCredentials.signaturePlaceholder(),
            b"",
        )

        message = SNMPv3WireMessage(
            self.authHeader,
            self.scopedPDU,
            OctetString(securityParameters.encode()),
        )

        wholeMsg = localizedCredentials.sign(message)
        decoded = SNMPv3WireMessage.decodeExact(wholeMsg)

    def test_empty_lc_verifySignature_raises_AuthenticationNotEnabled(self):
        data = bytes.fromhex(
            "30 81 83"
            "   02 01 03"
            "   30 10"
            "      02 04 18 27 36 45"
            "      02 02 01 e4"
            "      04 01 05"
            "      02 01 03"
            "   04 35"
            "      30 33"
            "         04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "               20 74 68 65 6d 20 61 6c 6c"
            "         02 02 01 27"
            "         02 02 01 28"
            "         04 08 61 75 74 68 55 73 65 72"
            "         04 02 86 00"
            "         04 00"
            "   30 35"
            "      04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "            20 74 68 65 6d 20 61 6c 6c"
            "      04 00"
            "      a0 16"
            "         02 01 00"
            "         02 01 00"
            "         02 01 00"
            "         30 0b"
            "            30 09"
            "               06 05 2a 03 04 05 06"
            "               05 00"
        )

        signature = subbytes(data, 75, 77)
        credentials = Credentials()
        localizedCredentials = credentials.localize(self.engineID)

        self.assertRaises(
            AuthenticationNotEnabled,
            localizedCredentials.verifySignature,
            signature,
        )

    def test_auth_lc_verifySignature_InvalidSignature_if_length_is_wrong(self):
        data = bytes.fromhex(
            "30 81 82"
            "   02 01 03"
            "   30 10"
            "      02 04 18 27 36 45"
            "      02 02 01 e4"
            "      04 01 05"
            "      02 01 03"
            "   04 34"
            "      30 32"
            "         04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "               20 74 68 65 6d 20 61 6c 6c"
            "         02 02 01 27"
            "         02 02 01 28"
            "         04 08 61 75 74 68 55 73 65 72"
            "         04 01 86"
            "         04 00"
            "   30 35"
            "      04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "            20 74 68 65 6d 20 61 6c 6c"
            "      04 00"
            "      a0 16"
            "         02 01 00"
            "         02 01 00"
            "         02 01 00"
            "         30 0b"
            "            30 09"
            "               06 05 2a 03 04 05 06"
            "               05 00"
        )

        signature = subbytes(data, 75, 76)
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        localizedCredentials = credentials.localize(self.engineID)

        self.assertRaises(
            InvalidSignature,
            localizedCredentials.verifySignature,
            signature,
        )

    def test_auth_lc_verifySignature_InvalidSignature_if_wrong_digest(self):
        data = bytes.fromhex(
            "30 81 83"
            "   02 01 03"
            "   30 10"
            "      02 04 18 27 36 45"
            "      02 02 01 e4"
            "      04 01 05"
            "      02 01 03"
            "   04 35"
            "      30 33"
            "         04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "               20 74 68 65 6d 20 61 6c 6c"
            "         02 02 01 27"
            "         02 02 01 28"
            "         04 08 61 75 74 68 55 73 65 72"
            "         04 02 12 34"
            "         04 00"
            "   30 35"
            "      04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "            20 74 68 65 6d 20 61 6c 6c"
            "      04 00"
            "      a0 16"
            "         02 01 00"
            "         02 01 00"
            "         02 01 00"
            "         30 0b"
            "            30 09"
            "               06 05 2a 03 04 05 06"
            "               05 00"
        )

        signature = subbytes(data, 75, 77)
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        localizedCredentials = credentials.localize(self.engineID)

        self.assertRaises(
            InvalidSignature,
            localizedCredentials.verifySignature,
            signature,
        )

    def test_auth_lc_verifySignature_does_nothing_if_correct(self):
        data = bytes.fromhex(
            "30 81 83"
            "   02 01 03"
            "   30 10"
            "      02 04 18 27 36 45"
            "      02 02 01 e4"
            "      04 01 05"
            "      02 01 03"
            "   04 35"
            "      30 33"
            "         04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "               20 74 68 65 6d 20 61 6c 6c"
            "         02 02 01 27"
            "         02 02 01 28"
            "         04 08 61 75 74 68 55 73 65 72"
            "         04 02 86 00"
            "         04 00"
            "   30 35"
            "      04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "            20 74 68 65 6d 20 61 6c 6c"
            "      04 00"
            "      a0 16"
            "         02 01 00"
            "         02 01 00"
            "         02 01 00"
            "         30 0b"
            "            30 09"
            "               06 05 2a 03 04 05 06"
            "               05 00"
        )

        signature = subbytes(data, 75, 77)
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        localizedCredentials = credentials.localize(self.engineID)
        localizedCredentials.verifySignature(signature)

    def test_empty_lc_decrypt_raises_PrivacyNotEnabled(self):
        credentials = Credentials()
        localizedCredentials = credentials.localize(self.engineID)

        self.assertRaises(
            PrivacyNotEnabled,
            localizedCredentials.decrypt,
            OctetString(),
            482,
            483,
            b"salt",
        )

    def test_auth_lc_encrypt_raises_PrivacyNotEnabled(self):
        credentials = AuthCredentials(DummyAuthProtocol, self.authSecret)
        localizedCredentials = credentials.localize(self.engineID)

        self.assertRaises(
            PrivacyNotEnabled,
            localizedCredentials.encrypt,
            OctetString(),
            495,
            496,
        )

    def test_priv_lc_decrypt_returns_the_correct_ScopedPDU(self):
        data = bytes.fromhex(
            "30 35"
            "   04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "         20 74 68 65 6d 20 61 6c 6c"
            "   04 00"
            "   a0 16"
            "      02 01 00"
            "      02 01 00"
            "      02 01 00"
            "      30 0b"
            "         30 09"
            "            06 05 2a 03 04 05 06"
            "            05 00"
        )

        encryptedPDU = OctetString(data)
        credentials = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        lc = credentials.localize(self.engineID)
        scopedPDU = lc.decrypt(encryptedPDU, 524, 524, b"salt")
        self.assertEqual(scopedPDU, self.scopedPDU)

    def test_priv_lc_encrypt_returns_OctetString_with_salt(self):
        data = bytes.fromhex(
            "30 35"
            "   04 19 4f 6e 65 20 52 69 6e 67 20 74 6f 20 72 75 6c 65"
            "         20 74 68 65 6d 20 61 6c 6c"
            "   04 00"
            "   a0 16"
            "      02 01 00"
            "      02 01 00"
            "      02 01 00"
            "      30 0b"
            "         30 09"
            "            06 05 2a 03 04 05 06"
            "            05 00"
        )

        credentials = AuthPrivCredentials(
            DummyAuthProtocol,
            DummyPrivProtocol,
            self.authSecret,
            self.privSecret,
        )

        lc = credentials.localize(self.engineID)
        encryptedPDU, salt = lc.encrypt(self.scopedPDU, 551, 551)
        self.assertEqual(encryptedPDU.data, data)
        self.assertEqual(salt, b"salt")

if __name__ == "__main__":
    unittest.main()
