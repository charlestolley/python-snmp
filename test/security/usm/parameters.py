__all__ = ["UsmSecurityParametersTest"]

import re
import unittest

from snmp.security.usm.parameters import *
from snmp.utils import subbytes

class UsmSecurityParametersTest(unittest.TestCase):
    def setUp(self):
        self.message = bytes.fromhex(re.sub("\n", "", """
            30 81 97
               02 01 03
               30 10
                  02 04 28 6e 48 41
                  02 02 05 dc
                  04 01 03
                  02 01 03
               04 2e
                  30 2c
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     02 02 05 d4
                     02 02 14 d0
                     04 08 73 6f 6d 65 55 73 65 72
                     04 02 9a 00
                     04 04 73 61 6c 74
               04 50
                  30 4e
                     04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44
                     04 00
                     a2 3a
                        02 04 26 cf 6e 26
                        02 01 00
                        02 01 00
                        30 2c
                           30 2a
                              06 07 2b 06 01 02 01 01 00
                              04 1f 54 68 69 73 20 73 74 72 69 6e 67
                                    20 64 65 73 63 72 69 62 65 73 20
                                    6d 79 20 73 79 73 74 65 6d
        """))

        self.encoding = subbytes(self.message, 26, 72)

        self.engineID = b"remoteEngineID"
        self.engineBoots = 1492
        self.engineTime = 5328
        self.userName = b"someUser"
        self.signature = b"\x9a\x00"
        self.salt = b"salt"

        self.securityParameters = UsmSecurityParameters(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            self.userName,
            self.signature,
            self.salt,
        )


    def test_decode_all_six_fields_defined_in_RFC3414(self):
        params = UsmSecurityParameters.decode(self.encoding)
        self.assertEqual(params.engineID, self.engineID)
        self.assertEqual(params.engineBoots, self.engineBoots)
        self.assertEqual(params.engineTime, self.engineTime)
        self.assertEqual(params.userName, self.userName)
        self.assertEqual(params.signature, self.signature)
        self.assertEqual(params.salt, self.salt)

    def test_encode_all_six_fields_defined_in_RFC3414(self):
        self.assertEqual(self.securityParameters.encode(), self.encoding)

    def test_two_objects_with_the_six_equal_fields_are_equal(self):
        self.assertEqual(
            UsmSecurityParameters.decode(self.encoding, copy=False),
            UsmSecurityParameters.decode(self.encoding, copy=True),
        )

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        self.assertEqual(
            eval(repr(self.securityParameters)),
            self.securityParameters,
        )

    def test_eval_repr_preserves_wholeMsg_and_signatureIndex(self):
        params = UsmSecurityParameters.decode(self.encoding)
        copy = eval(repr(params))

        self.assertIsNotNone(params.wholeMsg)
        self.assertEqual(copy.wholeMsg, params.wholeMsg)
        self.assertEqual(copy.signatureIndex, params.signatureIndex)

    def test_decode_preserves_reference_to_wholeMsg(self):
        params = UsmSecurityParameters.decode(self.encoding)
        self.assertIs(params.wholeMsg, self.message)

    def test_decode_stores_signatureIndex(self):
        params = UsmSecurityParameters.decode(self.encoding)
        self.assertEqual(params.signatureIndex, 64)

    def test_decode_with_copy_leaves_wholeMsg_and_signatureIndex_as_None(self):
        params = UsmSecurityParameters.decode(self.encoding, copy=True)
        self.assertIsNone(params.signatureIndex)
        self.assertIsNone(params.wholeMsg)

    def test_findSignature_returns_signature_as_subbytes(self):
        signature = UsmSecurityParameters.findSignature(self.encoding)
        self.assertEqual(signature, self.encoding[38:40])
        self.assertIs(signature.data, self.message)

    def test__str__is_not_the_same_as__repr__(self):
        self.assertNotEqual(
            str(self.securityParameters),
            repr(self.securityParameters),
        )

if __name__ == "__main__":
    unittest.main()
