__all__ = ["makeAesCfb192Test", "makeAesCfb256Test"]

import re
import unittest

from snmp.ber import decode, encode
from snmp.pdu import GetNextRequestPDU
from snmp.smi import OctetString, Sequence
from snmp.security.usm.auth import HmacSha

def makeAesCfb192Test(AesCfb192):
    class AesCfb192Test(unittest.TestCase):
        def setUp(self):
            self.authProtocol = HmacSha
            self.privProtocol = AesCfb192
            self.engineID = bytes(11) + b"\x02"
            self.secret = b"maplesyrup"

            pdu = GetNextRequestPDU(
                "1.3.6.1.2.1.2.2.1.2",
                "1.3.6.1.2.1.2.2.1.7",
                "1.3.6.1.2.1.2.2.1.8",
            )

            self.data = b"".join((
                OctetString(self.engineID).encode(),
                OctetString().encode(),
                pdu.encode()
            ))

            self.engineBoots = 918273645
            self.engineTime  = 546372819

        def test_two_objects_with_the_same_key_are_equal(self):
            key = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            a = self.privProtocol(key)
            b = self.privProtocol(key)
            self.assertEqual(a, b)

        def test_two_objects_with_different_keys_are_not_equal(self):
            ka = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            kb = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(b"strawberryjam"),
                self.engineID,
            )

            a = self.privProtocol(ka)
            b = self.privProtocol(kb)
            self.assertNotEqual(a, b)

        def test_decrypt_successfully_decrypts_an_example(self):
            privKey = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            priv = self.privProtocol(privKey)

            ciphertext = bytes.fromhex(re.sub(r"\n", "", """
                a0 09 a9 c3 b3 d3 53 71 08 29 1d 21 a8 85 55 97
                66 54 1e 09 57 9c af 73 ec 9f 86 dd 28 7e c0 e2
                59 35 d8 01 39 69 ff 16 ea 34 32 e4 b2 95 6c c9
                45 a9 aa 02 93 54 f5 9c a1 86 39 6f 9f 60 93 60
                cd 6a fb c1 71 f8 5b 68 fd 08 51 7f 00 00 00 00
            """))

            msgPrivParameters = bytes.fromhex("c4 14 b2 66 30 da 5e 39")

            plaintext = priv.decrypt(
                ciphertext,
                self.engineBoots,
                self.engineTime,
                msgPrivParameters,
            )

            tag, contents, _ = decode(plaintext)
            self.assertEqual(contents, self.data)

        def test_encrypt_successfully_encrypts_an_example(self):
            privKey = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            priv = self.privProtocol(privKey)

            original = encode(Sequence.TAG, self.data)
            ciphertext, msgPrivParameters = priv.encrypt(
                original,
                self.engineBoots,
                self.engineTime,
            )

            plaintext = priv.decrypt(
                ciphertext,
                self.engineBoots,
                self.engineTime,
                msgPrivParameters,
            )

            tag, contents, _ = decode(plaintext)
            self.assertEqual(contents, self.data)

    return AesCfb192Test

def makeAesCfb256Test(AesCfb256):
    class AesCfb256Test(unittest.TestCase):
        def setUp(self):
            self.authProtocol = HmacSha
            self.privProtocol = AesCfb256
            self.engineID = bytes(11) + b"\x02"
            self.secret = b"maplesyrup"

            pdu = GetNextRequestPDU(
                "1.3.6.1.2.1.2.2.1.2",
                "1.3.6.1.2.1.2.2.1.7",
                "1.3.6.1.2.1.2.2.1.8",
            )

            self.data = b"".join((
                OctetString(self.engineID).encode(),
                OctetString().encode(),
                pdu.encode()
            ))

            self.engineBoots = 918273645
            self.engineTime  = 546372819

        def test_two_objects_with_the_same_key_are_equal(self):
            key = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            a = self.privProtocol(key)
            b = self.privProtocol(key)
            self.assertEqual(a, b)

        def test_two_objects_with_different_keys_are_not_equal(self):
            ka = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            kb = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(b"strawberryjam"),
                self.engineID,
            )

            a = self.privProtocol(ka)
            b = self.privProtocol(kb)
            self.assertNotEqual(a, b)

        def test_decrypt_successfully_decrypts_an_example(self):
            privKey = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            priv = self.privProtocol(privKey)

            ciphertext = bytes.fromhex(re.sub(r"\n", "", """
                9c a3 bb 5d 8a 9c d3 79 7b 4b cd d6 56 88 30 33
                d7 b2 03 d0 8c 1a 3f 88 09 a6 25 a7 ed 06 4e 4f
                94 4c 7e 24 fb bf ca 4a 46 df 2d cb da d3 3d b1
                ba 52 d7 2b d8 e9 11 43 f8 fc 0f 0a 4c ee 0e 1f
                4d 51 0a 37 3c 04 09 54 a5 53 a5 b1 00 00 00 00
            """))

            msgPrivParameters = bytes.fromhex("2f c6 50 d9 b1 7e 0e 85")


            plaintext = priv.decrypt(
                ciphertext,
                self.engineBoots,
                self.engineTime,
                msgPrivParameters,
            )

            tag, contents, _ = decode(plaintext)
            self.assertEqual(contents, self.data)

        def test_encrypt_successfully_encrypts_an_example(self):
            privKey = self.privProtocol.localizeKey(
                self.authProtocol,
                self.authProtocol.computeKey(self.secret),
                self.engineID,
            )

            priv = self.privProtocol(privKey)

            original = encode(Sequence.TAG, self.data)
            ciphertext, msgPrivParameters = priv.encrypt(
                original,
                self.engineBoots,
                self.engineTime,
            )

            plaintext = priv.decrypt(
                ciphertext,
                self.engineBoots,
                self.engineTime,
                msgPrivParameters,
            )

            tag, contents, _ = decode(plaintext)
            self.assertEqual(contents, self.data)

    return AesCfb256Test
