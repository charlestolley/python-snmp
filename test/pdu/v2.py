__all__ = ["NullTypesTest", "VarBindListTest", "VarBindTest",]

import unittest
from snmp.ber import ParseError
from snmp.pdu.v2 import *
from snmp.smi.v2 import *
from snmp.types import *

class NullTypesTest(unittest.TestCase):
    def helper(self, cls, data):
        result = cls.decode(data)
        self.assertTrue(isinstance(result, cls))

    def testNoSuchObject(self):
        self.helper(NoSuchObject, b"\x80\x00")

    def testNoSuchInstance(self):
        self.helper(NoSuchInstance, b"\x81\x00")

    def testEndOfMibView(self):
        self.helper(EndOfMibView, b"\x82\x00")

class VarBindTest(unittest.TestCase):
    def setUp(self):
        self.ifDescr = OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
        self.varbind = VarBind(self.ifDescr.extend(1), OctetString(b"lo"))
        self.data = bytes.fromhex("""
            30 10 06 0a 2b 06 01 02 01 02 02 01 02 01 04 02 6c 6f
        """)

    def testRepr(self):
        self.assertEqual(eval(repr(self.varbind)), self.varbind)

    def testDecode(self):
        self.assertEqual(VarBind.decode(self.data), self.varbind)

    def testDecodeBadType(self):
        data = bytes.fromhex("30 06 06 01 00 01 01 00")
        self.assertRaises(ParseError, VarBind.decode, data)

    def testDecodeInteger(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 02 01 00"))
        self.assertTrue(isinstance(varbind.value, Integer))

    def testDecodeNull(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 05 01 00"))
        self.assertTrue(isinstance(varbind.value, Null))

    def testDecodeOID(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 06 01 00"))
        self.assertTrue(isinstance(varbind.value, OID))

    def testDecodeIpAddress(self):
        data = bytes.fromhex("30 09 06 01 00 40 04 00 00 00 00")
        varbind = VarBind.decode(data)
        self.assertTrue(isinstance(varbind.value, IpAddress))

    def testDecodeCounter32(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 41 01 00"))
        self.assertTrue(isinstance(varbind.value, Counter32))

    def testDecodeGauge32(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 42 01 00"))
        self.assertTrue(isinstance(varbind.value, Gauge32))

    def testDecodeTimeTicks(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 43 01 00"))
        self.assertTrue(isinstance(varbind.value, TimeTicks))

    def testDecodeOpaque(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 44 01 00"))
        self.assertTrue(isinstance(varbind.value, Opaque))

    def testDecodeCounter64(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 46 01 00"))
        self.assertTrue(isinstance(varbind.value, Counter64))

    def testDecodeNoSuchObject(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 80 01 00"))
        self.assertTrue(isinstance(varbind.value, NoSuchObject))

    def testDecodeNoSuchInstance(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 81 01 00"))
        self.assertTrue(isinstance(varbind.value, NoSuchInstance))

    def testDecodeEndOfMibView(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 82 01 00"))
        self.assertTrue(isinstance(varbind.value, EndOfMibView))

    def testEncode(self):
        self.assertEqual(self.varbind.encode(), self.data)

class VarBindListTest(unittest.TestCase):
    def setUp(self):
        ifEntry = OID(1, 3, 6, 1, 2, 1, 2, 2, 1)
        ifIndex = Integer(1)

        self.ifDescr = ifEntry.extend(2)
        self.ifMtu = ifEntry.extend(4)
        ifPhysAddress = ifEntry.extend(6)
        ifSpecific = ifEntry.extend(22)

        self.vblist = VarBindList(
            VarBind(self.ifDescr.appendIndex(ifIndex), OctetString(b"lo")),
            VarBind(self.ifMtu.appendIndex(ifIndex), Integer(1500)),
            VarBind(ifPhysAddress.appendIndex(ifIndex), OctetString(b"macadr")),
            VarBind(ifSpecific.appendIndex(ifIndex), zeroDotZero),
        )

        self.data = bytes.fromhex("""
            30 4b
               30 10 06 0a 2b 06 01 02 01 02 02 01 02 01 04 02 6c 6f
               30 10 06 0a 2b 06 01 02 01 02 02 01 04 01 02 02 05 dc
               30 14 06 0a 2b 06 01 02 01 02 02 01 06 01 04 06 6d 61 63 61 64 72
               30 0f 06 0a 2b 06 01 02 01 02 02 01 16 01 06 01 00
        """)

    def testConstructorDefaults(self):
        self.assertEqual(
            VarBindList(self.ifDescr, self.ifMtu),
            VarBindList(
                VarBind(self.ifDescr, Null()),
                VarBind(self.ifMtu, Null()),
            )
        )

    def testLength(self):
        self.assertEqual(len(self.vblist), 4)

    def testRepr(self):
        self.assertEqual(eval(repr(self.vblist)), self.vblist)

    def testGetItem(self):
        for i in range(len(self.vblist)):
            self.assertTrue(isinstance(self.vblist[i], VarBind))

        self.assertRaises(IndexError, self.vblist.__getitem__, len(self.vblist))

    def testBool(self):
        self.assertFalse(VarBindList())
        self.assertTrue(self.vblist)

    def testDecode(self):
        self.assertEqual(VarBindList.decode(self.data), self.vblist)

    def testEncode(self):
        self.assertEqual(self.vblist.encode(), self.data)

if __name__ == '__main__':
    unittest.main()
