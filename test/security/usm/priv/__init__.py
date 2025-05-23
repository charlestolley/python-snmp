__all__ = [
    "makeAesCfb128Test", "makeDesCbcTest",
    "AesCfb128CrossTest", "DesCbcCrossTest", "CrossAlgorithmTest",
]

import re
import unittest
from snmp.ber import *
from snmp.smi import *
from snmp.pdu import *
from snmp.security.usm.auth import HmacSha

def makeAesCfb128Test(AesCfb128):
    class AesCfb128Test(unittest.TestCase):
        def setUp(self):
            self.authProtocol = HmacSha
            self.privProtocol = AesCfb128
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
            key = self.authProtocol.localize(self.secret, self.engineID)
            a = self.privProtocol(key)
            b = self.privProtocol(key)
            self.assertEqual(a, b)

        def test_two_objects_with_different_keys_are_not_equal(self):
            ka = self.authProtocol.localize(self.secret, self.engineID)
            kb = self.authProtocol.localize(b"strawberryjam", self.engineID)
            a = self.privProtocol(ka)
            b = self.privProtocol(kb)
            self.assertNotEqual(a, b)

        def test_decrypt_successfully_decrypts_an_example(self):
            privKey = self.authProtocol.localize(self.secret, self.engineID)
            priv = self.privProtocol(privKey)

            ciphertext = bytes.fromhex(re.sub(r"\n", "", """
                45 80 ec 9b b4 8c 56 e2 02 68 cc d9 70 98 55 bd
                77 6f 73 75 26 1f 06 4b 62 62 9a 3b c6 e4 5d 65
                0b a7 58 49 cc 28 ea db 4b 64 c2 c2 2b 6e 04 30
                41 15 08 9b ca 45 c9 4a 58 f6 5c 5a e5 50 bb eb
                30 b4 bd 94 88 9a 3e c3 9a 89 29 39
            """))

            msgPrivParameters = bytes.fromhex(re.sub(r"\n", "", """
                30 50 91 db cc 0c 9b 87 
            """))

            plaintext = priv.decrypt(
                ciphertext,
                self.engineBoots,
                self.engineTime,
                msgPrivParameters,
            )

            tag, contents, _ = decode(plaintext)
            self.assertEqual(contents, self.data)

        def test_encrypt_successfully_encrypts_an_example(self):
            privKey = self.authProtocol.localize(self.secret, self.engineID)
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

    return AesCfb128Test

def makeDesCbcTest(DesCbc):
    class DesCbcTest(unittest.TestCase):
        def setUp(self):
            self.authProtocol = HmacSha
            self.privProtocol = DesCbc
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
            key = self.authProtocol.localize(self.secret, self.engineID)
            a = self.privProtocol(key)
            b = self.privProtocol(key)
            self.assertEqual(a, b)

        def test_two_objects_with_different_keys_are_not_equal(self):
            ka = self.authProtocol.localize(self.secret, self.engineID)
            kb = self.authProtocol.localize(b"strawberryjam", self.engineID)
            a = self.privProtocol(ka)
            b = self.privProtocol(kb)
            self.assertNotEqual(a, b)

        def test_decrypt_successfully_decrypts_an_example(self):
            privKey = self.authProtocol.localize(self.secret, self.engineID)
            priv = self.privProtocol(privKey)

            ciphertext = bytes.fromhex(re.sub(r"\n", "", """
                14 4e f2 86 ad 12 47 ba 23 d6 41 51 67 17 1d 15
                aa 91 c7 fb ed 3e f2 1f 59 7f 96 ac a3 11 8d cb
                37 26 62 15 cc 32 0b 85 4a 70 91 39 82 a6 15 90
                aa 9d 0d a1 55 d2 9c 74 4f 32 2c a9 17 d9 7b 72
                2d b6 59 7d 00 c4 93 05 18 41 da 11 08 85 a8 4a 
            """))

            msgPrivParameters = bytes.fromhex(re.sub(r"\n", "", """
                36 bb be 6d f8 89 34 b6 
            """))

            plaintext = priv.decrypt(
                ciphertext,
                self.engineBoots,
                self.engineTime,
                msgPrivParameters,
            )

            tag, contents, _ = decode(plaintext)
            self.assertEqual(contents, self.data)

        def test_encrypt_successfully_encrypts_an_example(self):
            privKey = self.authProtocol.localize(self.secret, self.engineID)
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

    return DesCbcTest

try:
    from snmp.security.usm.priv.openssl.aes import (
        AesCfb128 as AesCfb128OpenSSL,
    )
except ImportError:
    AesCfb128OpenSSL = None

try:
    from snmp.security.usm.priv.pycryptodome.aes import (
        AesCfb128 as AesCfb128PyCrypto,
    )
except ImportError:
    AesCfb128PyCrypto = None

class AesCfb128CrossTest(unittest.TestCase):
    def setUp(self):
        if AesCfb128OpenSSL is None:
            self.skipTest("OpenSSL FFI is not installed")

        if AesCfb128PyCrypto is None:
            self.skipTest("pycryptodome is not installed")

        self.authProtocol = HmacSha
        self.engineID = bytes(11) + b"\x02"
        self.secret = b"maplesyrup"

    def test_two_objects_with_the_same_key_are_equal(self):
        key = self.authProtocol.localize(self.secret, self.engineID)
        a = AesCfb128OpenSSL(key)
        b = AesCfb128PyCrypto(key)
        self.assertEqual(a, b)
        self.assertEqual(b, a)

    def test_two_objects_with_different_keys_are_not_equal(self):
        ka = self.authProtocol.localize(self.secret, self.engineID)
        kb = self.authProtocol.localize(b"strawberryjam", self.engineID)
        a = AesCfb128OpenSSL(ka)
        b = AesCfb128PyCrypto(kb)
        self.assertNotEqual(a, b)
        self.assertNotEqual(b, a)

try:
    from snmp.security.usm.priv.openssl.des import DesCbc as DesCbcOpenSSL
except ImportError:
    DesCbcOpenSSL = None

try:
    from snmp.security.usm.priv.pycryptodome.des import (
        DesCbc as DesCbcPyCrypto,
    )
except ImportError:
    DesCbcPyCrypto = None

class DesCbcCrossTest(unittest.TestCase):
    def setUp(self):
        if DesCbcOpenSSL is None:
            self.skipTest("OpenSSL FFI is not installed")

        if DesCbcPyCrypto is None:
            self.skipTest("pycryptodome is not installed")

        self.authProtocol = HmacSha
        self.engineID = bytes(11) + b"\x02"
        self.secret = b"maplesyrup"

    def test_two_objects_with_the_same_key_are_equal(self):
        key = self.authProtocol.localize(self.secret, self.engineID)
        a = DesCbcOpenSSL(key)
        b = DesCbcPyCrypto(key)
        self.assertEqual(a, b)
        self.assertEqual(b, a)

    def test_two_objects_with_different_keys_are_not_equal(self):
        ka = self.authProtocol.localize(self.secret, self.engineID)
        kb = self.authProtocol.localize(b"strawberryjam", self.engineID)
        a = DesCbcOpenSSL(ka)
        b = DesCbcPyCrypto(kb)
        self.assertNotEqual(a, b)
        self.assertNotEqual(b, a)

class CrossAlgorithmTest(unittest.TestCase):
    def setUp(self):
        if AesCfb128OpenSSL is None or DesCbcOpenSSL is None:
            self.skipTest("OpenSSL FFI is not installed")

        if AesCfb128PyCrypto is None or DesCbcPyCrypto is None:
            self.skipTest("pycryptodome is not installed")

        self.authProtocol = HmacSha
        self.engineID = bytes(11) + b"\x02"
        self.secret = b"maplesyrup"

    def test_two_objects_with_different_algorithms_are_not_equal(self):
        key = self.authProtocol.localize(self.secret, self.engineID)
        a = AesCfb128OpenSSL(key)
        b = AesCfb128PyCrypto(key)
        c = DesCbcOpenSSL(key)
        d = DesCbcPyCrypto(key)

        self.assertNotEqual(a, c)
        self.assertNotEqual(a, d)
        self.assertNotEqual(b, c)
        self.assertNotEqual(b, d)
        self.assertNotEqual(c, a)
        self.assertNotEqual(c, b)
        self.assertNotEqual(d, a)
        self.assertNotEqual(d, b)
