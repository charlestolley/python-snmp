__all__ = [
    "BulkPDUTest", "NullTypesTest", "PDUTest", "PDUTypesTest",
    "PDUClassesTest", "VarBindListTest", "VarBindTest",
]

import re
import unittest
from snmp.ber import ParseError
from snmp.pdu import *
from snmp.smi import *

class NullTypesTest(unittest.TestCase):
    def helper(self, cls, data):
        result = cls.decode(data)
        self.assertEqual(result, cls())

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
        self.data = bytes.fromhex(re.sub(r"\n", "", """
            30 10 06 0a 2b 06 01 02 01 02 02 01 02 01 04 02 6c 6f
        """))

    def testRepr(self):
        self.assertEqual(eval(repr(self.varbind)), self.varbind)

    def testDecode(self):
        self.assertEqual(VarBind.decode(self.data), self.varbind)

    def testDecodeBadType(self):
        data = bytes.fromhex("30 06 06 01 00 01 01 00")
        self.assertRaises(ParseError, VarBind.decode, data)

    def testDecodeInteger(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 02 01 00"))
        self.assertEqual(varbind.value, Integer(0))

    def testDecodeNull(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 05 01 00"))
        self.assertEqual(varbind.value, Null())

    def testDecodeOID(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 06 01 00"))
        self.assertEqual(varbind.value, zeroDotZero)

    def testDecodeIpAddress(self):
        data = bytes.fromhex("30 09 06 01 00 40 04 00 00 00 00")
        varbind = VarBind.decode(data)
        self.assertEqual(varbind.value, IpAddress("0.0.0.0"))

    def testDecodeCounter32(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 41 01 00"))
        self.assertEqual(varbind.value, Counter32(0))

    def testDecodeGauge32(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 42 01 00"))
        self.assertEqual(varbind.value, Gauge32(0))

    def testDecodeTimeTicks(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 43 01 00"))
        self.assertEqual(varbind.value, TimeTicks(0))

    def testDecodeOpaque(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 44 01 00"))
        self.assertEqual(varbind.value, Opaque(b"\x00"))

    def testDecodeCounter64(self):
        varbind = VarBind.decode(bytes.fromhex("30 06 06 01 00 46 01 00"))
        self.assertEqual(varbind.value, Counter64(0))

    def testDecodeNoSuchObject(self):
        varbind = VarBind.decode(bytes.fromhex("30 05 06 01 00 80 00"))
        self.assertEqual(varbind.value, NoSuchObject())

    def testDecodeNoSuchInstance(self):
        varbind = VarBind.decode(bytes.fromhex("30 05 06 01 00 81 00"))
        self.assertEqual(varbind.value, NoSuchInstance())

    def testDecodeEndOfMibView(self):
        varbind = VarBind.decode(bytes.fromhex("30 05 06 01 00 82 00"))
        self.assertEqual(varbind.value, EndOfMibView())

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
            VarBind(self.ifDescr.withIndex(ifIndex), OctetString(b"lo")),
            VarBind(self.ifMtu.withIndex(ifIndex), Integer(1500)),
            VarBind(ifPhysAddress.withIndex(ifIndex), OctetString(b"macadr")),
            VarBind(ifSpecific.withIndex(ifIndex), zeroDotZero),
        )

        self.data = bytes.fromhex(re.sub(r"\n", "", """
            30 4b
               30 10 06 0a 2b 06 01 02 01 02 02 01 02 01 04 02 6c 6f
               30 10 06 0a 2b 06 01 02 01 02 02 01 04 01 02 02 05 dc
               30 14 06 0a 2b 06 01 02 01 02 02 01 06 01 04 06 6d 61 63 61 64 72
               30 0f 06 0a 2b 06 01 02 01 02 02 01 16 01 06 01 00
        """))

    def testConstructorDefaults(self):
        self.assertEqual(
            VarBindList("1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.4"),
            VarBindList(
                VarBind(self.ifDescr, Null()),
                VarBind(self.ifMtu, Null()),
            )
        )

    def testBool(self):
        self.assertFalse(VarBindList())
        self.assertTrue(self.vblist)

    def testGetItem(self):
        for i in range(len(self.vblist)):
            self.assertTrue(isinstance(self.vblist[i], VarBind))

        self.assertRaises(IndexError, self.vblist.__getitem__, len(self.vblist))

    def testLength(self):
        self.assertEqual(len(self.vblist), 4)

    def testRepr(self):
        self.assertEqual(eval(repr(self.vblist)), self.vblist)

    def testDecode(self):
        self.assertEqual(VarBindList.decode(self.data), self.vblist)

    def testEncode(self):
        self.assertEqual(self.vblist.encode(), self.data)

class PDUTest(unittest.TestCase):
    def setUp(self):
        ifDescr = OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
        var = VarBind(ifDescr.extend(29), NoSuchInstance())

        self.pdu = ResponsePDU(
            requestID=0x709b4a44,
            errorStatus=5,
            variableBindings=VarBindList(var)
        )

        self.data = bytes.fromhex(re.sub(r"\n", "", """
            a2 1e
               02 04 70 9b 4a 44
               02 01 05
               02 01 00
               30 10
                  30 0e
                     06 0a 2b 06 01 02 01 02 02 01 02 1d
                     81 00 
        """))

    # see RFC 3416 section 3 (p. 8)
    def testErrorStatusEnum(self):
        self.assertEqual(ErrorStatus.noError,                0)
        self.assertEqual(ErrorStatus.tooBig,                 1)
        self.assertEqual(ErrorStatus.noSuchName,             2)
        self.assertEqual(ErrorStatus.badValue,               3)
        self.assertEqual(ErrorStatus.readOnly,               4)
        self.assertEqual(ErrorStatus.genErr,                 5)
        self.assertEqual(ErrorStatus.noAccess,               6)
        self.assertEqual(ErrorStatus.wrongType,              7)
        self.assertEqual(ErrorStatus.wrongLength,            8)
        self.assertEqual(ErrorStatus.wrongEncoding,          9)
        self.assertEqual(ErrorStatus.wrongValue,            10)
        self.assertEqual(ErrorStatus.noCreation,            11)
        self.assertEqual(ErrorStatus.inconsistentValue,     12)
        self.assertEqual(ErrorStatus.resourceUnavailable,   13)
        self.assertEqual(ErrorStatus.commitFailed,          14)
        self.assertEqual(ErrorStatus.undoFailed,            15)
        self.assertEqual(ErrorStatus.authorizationError,    16)
        self.assertEqual(ErrorStatus.notWritable,           17)
        self.assertEqual(ErrorStatus.inconsistentName,      18)

    def testIgnoreUnusedArgs(self):
        pdu = ResponsePDU(
            "the first of four nonsense arguments",
            1984,
            OID(1, 2, 3, 4, 5),
            unittest.main,
            requestID=self.pdu.requestID,
            errorStatus=self.pdu.errorStatus,
            errorIndex=self.pdu.errorIndex,
            variableBindings=self.pdu.variableBindings,
        )

        self.assertEqual(pdu, self.pdu)

    def testRepr(self):
        self.assertEqual(eval(repr(self.pdu)), self.pdu)

    def testDecode(self):
        self.assertEqual(self.pdu, ResponsePDU.decode(self.data))

    def testEncode(self):
        self.assertEqual(self.pdu.encode(), self.data)

class BulkPDUTest(unittest.TestCase):
    def setUp(self):
        self.pdu = GetBulkRequestPDU(
            requestID = 0x4bddc597,
            maxRepetitions=10,
            variableBindings=VarBindList(
                OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 2),
                OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 4),
            ),
        )

        self.data = bytes.fromhex(re.sub(r"\n", "", """
            a5 2c
               02 04 4b dd c5 97
               02 01 00
               02 01 0a
               30 1e
                  30 0d
                     06 09 2b 06 01 02 01 02 02 01 02
                     05 00
                  30 0d
                     06 09 2b 06 01 02 01 02 02 01 04
                     05 00
        """))

    def testIgnoreUnusedArgs(self):
        pdu = GetBulkRequestPDU(
            "nonsense argument for BulkPDU",
            requestID=self.pdu.requestID,
            nonRepeaters=self.pdu.nonRepeaters,
            maxRepetitions=self.pdu.maxRepetitions,
            variableBindings=self.pdu.variableBindings,
        )

        self.assertEqual(pdu, self.pdu)

    def testRepr(self):
        self.assertEqual(eval(repr(self.pdu)), self.pdu)

    def testDecode(self):
        self.assertEqual(self.pdu, GetBulkRequestPDU.decode(self.data))

    def testEncode(self):
        self.assertEqual(self.pdu.encode(), self.data)

class PDUTypesTest(unittest.TestCase):
    def testGetRequest(self):
        data = bytes.fromhex("a0 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = GetRequestPDU.decode(data)
        self.assertEqual(pdu, GetRequestPDU())

    def testGetNextRequest(self):
        data = bytes.fromhex("a1 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = GetNextRequestPDU.decode(data)
        self.assertEqual(pdu, GetNextRequestPDU())

    def testResponse(self):
        data = bytes.fromhex("a2 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = ResponsePDU.decode(data)
        self.assertEqual(pdu, ResponsePDU())

    def testSetRequest(self):
        data = bytes.fromhex("a3 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = SetRequestPDU.decode(data)
        self.assertEqual(pdu, SetRequestPDU())

    def testTrap(self):
        data = bytes.fromhex("a4 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = TrapPDU.decode(data)
        self.assertEqual(pdu, TrapPDU())

    def testGetBulkRequest(self):
        data = bytes.fromhex("a5 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = GetBulkRequestPDU.decode(data)
        self.assertEqual(pdu, GetBulkRequestPDU())

    def testInformRequest(self):
        data = bytes.fromhex("a6 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = InformRequestPDU.decode(data)
        self.assertEqual(pdu, InformRequestPDU())

    def testSNMPv2Trap(self):
        data = bytes.fromhex("a7 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = SNMPv2TrapPDU.decode(data)
        self.assertEqual(pdu, SNMPv2TrapPDU())

    def testReport(self):
        data = bytes.fromhex("a8 0b 02 01 00 02 01 00 02 01 00 30 00")
        pdu = ReportPDU.decode(data)
        self.assertEqual(pdu, ReportPDU())

# see RFC 3411 section 2.8 (pp. 13-14)
class PDUClassesTest(unittest.TestCase):
    def testReadClass(self):
        self.assertTrue(isinstance(GetRequestPDU(), Read))
        self.assertTrue(isinstance(GetNextRequestPDU(), Read))
        self.assertTrue(isinstance(GetBulkRequestPDU(), Read))

    def testWriteClass(self):
        self.assertTrue(isinstance(SetRequestPDU(), Write))

    def testResponseClass(self):
        self.assertTrue(isinstance(ResponsePDU(), Response))
        self.assertTrue(isinstance(ReportPDU(), Response))

    def testNotificationClass(self):
        self.assertTrue(isinstance(InformRequestPDU(), Notification))
        self.assertTrue(isinstance(TrapPDU(), Notification))
        self.assertTrue(isinstance(SNMPv2TrapPDU(), Notification))

    def testInternalClass(self):
        self.assertTrue(isinstance(ReportPDU(), Internal))

    def testConfirmedClass(self):
        self.assertTrue(isinstance(GetRequestPDU(), Confirmed))
        self.assertTrue(isinstance(GetNextRequestPDU(), Confirmed))
        self.assertTrue(isinstance(GetBulkRequestPDU(), Confirmed))
        self.assertTrue(isinstance(SetRequestPDU(), Confirmed))
        self.assertTrue(isinstance(InformRequestPDU(), Confirmed))

    def testUnconfirmedClass(self):
        self.assertFalse(isinstance(ResponsePDU(), Confirmed))
        self.assertFalse(isinstance(TrapPDU(), Confirmed))
        self.assertFalse(isinstance(SNMPv2TrapPDU(), Confirmed))
        self.assertFalse(isinstance(ReportPDU(), Confirmed))

if __name__ == '__main__':
    unittest.main()
