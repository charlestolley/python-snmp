__all__ = [
    "makeAesCfb192Test", "makeAesCfb256Test",
    "CiscoAesCfb192CrossTest", "CiscoAesCfb256CrossTest",
    "CiscoCrossAlgorithmTest",
]

import re
import unittest

from snmp.ber import decode, encode
from snmp.pdu import GetNextRequestPDU
from snmp.smi import OctetString, Sequence
from snmp.security.usm.auth import HmacMd5, HmacSha

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
                31 fb d8 1e 97 69 61 52 85 86 ca 0b 1a 54 88 98
                3b 35 62 d3 a3 66 1a a3 79 76 a5 bc 37 9e 83 50
                40 58 c0 2c d8 aa d6 11 7f ab 7a 56 af 40 39 3d
                49 81 33 27 63 c3 82 52 c9 56 62 ec d0 8e 9d e7
                3a bb 19 49 17 10 e1 de 11 44 1a 27 00 00 00 00
            """))

            msgPrivParameters = bytes.fromhex("35 06 8e 3e 5f a4 5a 7f")

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
                39 3e 67 06 11 a7 6b 2d 66 17 f8 d4 2f 67 c2 7e
                1e 0d f7 83 d6 3e 63 16 af 29 39 67 9a 52 5a 3e
                68 cd d4 fe 79 14 1d da d5 ed 0c 27 dd f1 01 60
                0c 65 ea db b3 cb 54 8d 38 b2 73 8b 31 dd 7a c3
                3c 6d c8 8b fb d7 49 6b c9 ce 36 4a 00 00 00 00
            """))

            msgPrivParameters = bytes.fromhex("ea 77 90 a9 ca be 51 b4")


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

        def test_localizeKey_generates_the_expected_HmacMd5_key(self):
            key = self.privProtocol.localizeKey(
                HmacMd5,
                HmacMd5.computeKey(self.secret),
                self.engineID,
            )

            expected = bytes.fromhex(re.sub("\n", "", """
                52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b
                79 ef f4 4a 90 65 0e e0 a3 a4 0a bf ac 5a cc 12
            """))

            self.assertEqual(key, expected)

        def test_localizeKey_generates_the_expected_HmacSha_key(self):
            key = self.privProtocol.localizeKey(
                HmacSha,
                HmacSha.computeKey(self.secret),
                self.engineID,
            )

            expected = bytes.fromhex(re.sub("\n", "", """
                66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f
                9b 8b 6d 78 93 6b a6 e7 d1 9d fd 9c d2 d5 06 55 47 74 3f b5
            """))

            self.assertEqual(key, expected)

    return AesCfb256Test

try:
    from snmp.security.usm.cisco.priv.openssl.aes import (
        CiscoAesCfb192 as AesCfb192OpenSSL,
    )
except ImportError:
    AesCfb192OpenSSL = None

try:
    from snmp.security.usm.cisco.priv.pycryptodome.aes import (
        CiscoAesCfb192 as AesCfb192PyCrypto,
    )
except ImportError:
    AesCfb192PyCrypto = None

class CiscoAesCfb192CrossTest(unittest.TestCase):
    def setUp(self):
        if AesCfb192OpenSSL is None:
            self.skipTest("OpenSSL FFI is not installed")

        if AesCfb192PyCrypto is None:
            self.skipTest("pycryptodome is not installed")

        self.authProtocol = HmacSha
        self.engineID = bytes(11) + b"\x02"
        self.secret = b"maplesyrup"

    def test_two_objects_with_the_same_key_are_equal(self):
        key = AesCfb192OpenSSL.localizeKey(
            self.authProtocol,
            self.authProtocol.computeKey(self.secret),
            self.engineID,
        )

        a = AesCfb192OpenSSL(key)
        b = AesCfb192PyCrypto(key)
        self.assertEqual(a, b)
        self.assertEqual(b, a)

    def test_two_objects_with_different_keys_are_not_equal(self):
        ka = AesCfb192OpenSSL.localizeKey(
            self.authProtocol,
            self.authProtocol.computeKey(self.secret),
            self.engineID,
        )

        kb = AesCfb192PyCrypto.localizeKey(
            self.authProtocol,
            self.authProtocol.computeKey(b"strawberryjam"),
            self.engineID,
        )

        a = AesCfb192OpenSSL(ka)
        b = AesCfb192PyCrypto(kb)
        self.assertNotEqual(a, b)
        self.assertNotEqual(b, a)

try:
    from snmp.security.usm.cisco.priv.openssl.aes import (
        CiscoAesCfb256 as AesCfb256OpenSSL,
    )
except ImportError:
    AesCfb256OpenSSL = None

try:
    from snmp.security.usm.cisco.priv.pycryptodome.aes import (
        CiscoAesCfb256 as AesCfb256PyCrypto,
    )
except ImportError:
    AesCfb256PyCrypto = None

class CiscoAesCfb256CrossTest(unittest.TestCase):
    def setUp(self):
        if AesCfb256OpenSSL is None:
            self.skipTest("OpenSSL FFI is not installed")

        if AesCfb256PyCrypto is None:
            self.skipTest("pycryptodome is not installed")

        self.authProtocol = HmacSha
        self.engineID = bytes(11) + b"\x02"
        self.secret = b"maplesyrup"

    def test_two_objects_with_the_same_key_are_equal(self):
        key = AesCfb256OpenSSL.localizeKey(
            self.authProtocol,
            self.authProtocol.computeKey(self.secret),
            self.engineID,
        )

        a = AesCfb256OpenSSL(key)
        b = AesCfb256PyCrypto(key)
        self.assertEqual(a, b)
        self.assertEqual(b, a)

    def test_two_objects_with_different_keys_are_not_equal(self):
        ka = AesCfb256OpenSSL.localizeKey(
            self.authProtocol,
            self.authProtocol.computeKey(self.secret),
            self.engineID,
        )

        kb = AesCfb256PyCrypto.localizeKey(
            self.authProtocol,
            self.authProtocol.computeKey(b"strawberryjam"),
            self.engineID,
        )

        a = AesCfb256OpenSSL(ka)
        b = AesCfb256PyCrypto(kb)
        self.assertNotEqual(a, b)
        self.assertNotEqual(b, a)

class CiscoCrossAlgorithmTest(unittest.TestCase):
    def setUp(self):
        if AesCfb192OpenSSL is None or AesCfb256OpenSSL is None:
            self.skipTest("OpenSSL FFI is not installed")

        if AesCfb192PyCrypto is None or AesCfb256PyCrypto is None:
            self.skipTest("pycryptodome is not installed")

        self.authProtocol = HmacSha
        self.engineID = bytes(11) + b"\x02"
        self.secret = b"maplesyrup"

    def test_two_objects_with_different_algorithms_are_not_equal(self):
        key = AesCfb256OpenSSL.localizeKey(
            self.authProtocol,
            self.authProtocol.computeKey(self.secret),
            self.engineID,
        )

        a = AesCfb192OpenSSL(key)
        b = AesCfb192PyCrypto(key)
        c = AesCfb256OpenSSL(key)
        d = AesCfb256PyCrypto(key)

        self.assertNotEqual(a, c)
        self.assertNotEqual(a, d)
        self.assertNotEqual(b, c)
        self.assertNotEqual(b, d)
        self.assertNotEqual(c, a)
        self.assertNotEqual(c, b)
        self.assertNotEqual(d, a)
        self.assertNotEqual(d, b)
