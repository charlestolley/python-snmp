__all__ = ["SNMPv3InterpreterTest", "SNMPv3MessageSorterTest"]

import re
import unittest

from snmp.ber import Tag
from snmp.pdu import *
from snmp.security import SecurityModel
from snmp.security.levels import *
from snmp.security.usm import UserBasedSecurityModule
from snmp.security.usm.stats import *
from snmp.smi import *
from snmp.v3.interpreter import *
from snmp.v3.message import *

from ..security.usm import DummyAuthProtocol, DummyPrivProtocol

class SNMPv3InterpreterTest(unittest.TestCase):
    def setUp(self):
        self.engineID = b"interpreter"
        self.usm = UserBasedSecurityModule()
        self.usm.addUser(
            b"chuck",
            "",
            authProtocol=DummyAuthProtocol,
            privProtocol=DummyPrivProtocol,
            secret=b"unintelligible",
        )

        self.interpreter = SNMPv3Interpreter(self.usm)

        self.pdu = ResponsePDU(
            ("1.3.6.1.2.1.1.1.0", OctetString(b"interpreter test")),
            ("1.2.3.4.5.6", Integer(123456)),
            requestID=33,
        )

        self.message = SNMPv3Message(
            HeaderData(37, 1472, MessageFlags(authPriv), SecurityModel.USM),
            ScopedPDU(self.pdu, self.engineID),
            self.engineID,
            SecurityName(b"chuck", "")
        )

        self.data = bytes.fromhex(re.sub("\n", "", """
            30 81 86
               02 01 03
               30 0d
                  02 01 25
                  02 02 05 c0
                  04 01 03
                  02 01 03
               04 26
                  30 24
                     04 0b 69 6e 74 65 72 70 72 65 74 65 72
                     02 01 00
                     02 01 00
                     04 05 63 68 75 63 6b
                     04 02 89 00
                     04 04 73 61 6c 74
               04 4a
                  30 48
                     04 0b 69 6e 74 65 72 70 72 65 74 65 72
                     04 00
                     a2 37
                        02 01 21
                        02 01 00
                        02 01 00
                        30 2c
                           30 1c
                              06 08 2b 06 01 02 01 01 01 00
                              04 10 69 6e 74 65 72 70 72 65
                                    74 65 72 20 74 65 73 74
                           30 0c
                              06 05 2a 03 04 05 06
                              02 03 01 e2 40
        """))

    def test_decode_converts_bytes_to_SNMPv3Message(self):
        self.assertEqual(self.interpreter.decode(self.data), self.message)

    def test_encode_produces_a_valid_SNMPv3WireMessage_encoding(self):
        data = self.interpreter.encode(self.message)
        SNMPv3WireMessage.decodeExact(data)

    def test_pdu_extracts_the_pdu_from_an_SNMPv3Message(self):
        self.assertEqual(self.interpreter.pdu(self.message), self.pdu)

    def test_makeReport(self):
        engineID = b"unknown"
        context = b"irrelevant"
        namespace = "everyone"
        securityModel = SecurityModel.USM

        pdu = GetRequestPDU("1.3.6.1.2.1.1.1.0", "1.2.3.4.5.6", requestID=94)
        message = SNMPv3Message(
            HeaderData(
                97,
                1472,
                MessageFlags(authNoPriv, True),
                securityModel,
            ),
            ScopedPDU(pdu, engineID, context),
            engineID,
            SecurityName(b"chuck", namespace),
        )

        report_message = self.interpreter.makeReport(
            message,
            (usmStatsUnknownEngineIDsInstance, Integer(9)),
        )

        self.assertEqual(report_message.header.msgID, 97)
        self.assertEqual(report_message.header.maxSize, 1472)
        self.assertTrue(report_message.header.flags.authFlag)
        self.assertFalse(report_message.header.flags.privFlag)
        self.assertFalse(report_message.header.flags.reportableFlag)
        self.assertEqual(report_message.header.securityModel, securityModel)
        self.assertEqual(report_message.scopedPDU.pdu.TAG, ReportPDU.TAG)
        self.assertEqual(report_message.scopedPDU.pdu.requestID, 94)

        self.assertEqual(
            report_message.scopedPDU.pdu.errorStatus,
            ErrorStatus.noError,
        )

        self.assertEqual(report_message.scopedPDU.pdu.errorIndex, 0)
        self.assertEqual(len(report_message.scopedPDU.pdu.variableBindings), 1)

        self.assertEqual(
            report_message.scopedPDU.pdu.variableBindings[0].name,
            usmStatsUnknownEngineIDsInstance,
        )

        self.assertEqual(
            report_message.scopedPDU.pdu.variableBindings[0].value,
            Integer(9),
        )

        self.assertEqual(report_message.scopedPDU.contextEngineID, engineID)
        self.assertEqual(report_message.scopedPDU.contextName, context)
        self.assertEqual(report_message.securityEngineID, engineID)
        self.assertEqual(report_message.securityName.userName, b"chuck")
        self.assertEqual(len(report_message.securityName.namespaces), 1)
        self.assertIn(namespace, report_message.securityName.namespaces)

class SNMPv3MessageSorterTest(unittest.TestCase):
    class Channel:
        def __init__(self):
            self.data = None

        def send(self, data):
            self.data = data

    class Interpreter:
        class Message(Sequence):
            pduTypes = {
                cls.TAG: cls for cls in (
                    GetRequestPDU,
                    GetNextRequestPDU,
                    GetBulkRequestPDU,
                    ResponsePDU,
                    ReportPDU,
                    SNMPv2TrapPDU,
                )
            }

            def __init__(self, pdu):
                self.pdu = pdu

            def __iter__(self):
                yield self.pdu

            def __len__(self):
                return 1

            @classmethod
            def deserialize(cls, data):
                tag, _ = Tag.decode(data)
                pduType = cls.pduTypes[tag]
                return cls(pduType.decodeExact(data))

        def __init__(self):
            self.exception = None

        def decode(self, data):
            if (self.exception is not None
            and isinstance(self.exception, ReportMessage)):
                raise self.exception

            return self.Message.decodeExact(data)

        def encode(self, message):
            return message.encode()

        def makeReport(self, message, vb):
            if self.exception is not None:
                raise self.exception

            return self.Message(ReportPDU(vb))

        def pdu(self, message):
            return message.pdu

    class Listener:
        def __init__(self):
            self.count = 0

        def hear(self, message, channel):
            self.count += 1

    def setUp(self):
        self.channel = self.Channel()
        self.interpreter = self.Interpreter()
        self.sorter = SNMPv3MessageSorter(self.interpreter)

    def test_sorter_forwards_messages_to_the_right_subscriber(self):
        get_listener = self.Listener()
        get_next_listener = self.Listener()
        response_listener = self.Listener()

        self.sorter.register(GetRequestPDU, get_listener)
        self.sorter.register(GetNextRequestPDU, get_next_listener)
        self.sorter.register(ResponsePDU, response_listener)

        msg = self.Interpreter.Message(GetRequestPDU("1.3.6.1.2.1.1.1.0"))
        self.sorter.hear(msg.encode(), self.channel)

        self.assertEqual(get_listener.count, 1)
        self.assertEqual(get_next_listener.count, 0)
        self.assertEqual(response_listener.count, 0)

        msg = self.Interpreter.Message(
            ResponsePDU(
                ("1.3.6.1.2.1.1.1.0", OctetString(b"description")),
            )
        )

        self.sorter.hear(msg.encode(), self.channel)

        self.assertEqual(get_listener.count, 1)
        self.assertEqual(get_next_listener.count, 0)
        self.assertEqual(response_listener.count, 1)

    def test_do_not_increment_unknownHandlers_for_response_type(self):
        pdu = ResponsePDU(("1.2.3.4.5.6", Integer(123456)))
        msg = self.Interpreter.Message(pdu).encode()

        self.assertEqual(self.sorter.unknownHandlers, 0)
        self.sorter.hear(msg, self.channel)
        self.assertEqual(self.sorter.unknownHandlers, 0)

    def test_increment_unknownHandlers_for_unregistered_request_type(self):
        get_listener = self.Listener()
        get_next_listener = self.Listener()
        response_listener = self.Listener()

        self.sorter.register(GetRequestPDU, get_listener)
        self.sorter.register(GetNextRequestPDU, get_next_listener)
        self.sorter.register(ResponsePDU, response_listener)

        pdu = SNMPv2TrapPDU(("1.2.3.4.5.6", Integer(123456)))
        msg = self.Interpreter.Message(pdu).encode()

        self.assertEqual(self.sorter.unknownHandlers, 0)
        self.sorter.hear(msg, self.channel)
        self.assertEqual(self.sorter.unknownHandlers, 1)

    def test_send_report_for_unregistered_confirmed_pdu(self):
        get_listener = self.Listener()
        get_next_listener = self.Listener()
        response_listener = self.Listener()

        self.sorter.register(GetRequestPDU, get_listener)
        self.sorter.register(GetNextRequestPDU, get_next_listener)
        self.sorter.register(ResponsePDU, response_listener)

        pdu = SNMPv2TrapPDU(("1.2.3.4.5.6", Integer(123456)))
        msg = self.interpreter.Message(pdu).encode()

        for i in range(6):
            self.sorter.hear(msg, self.channel)

        self.assertEqual(self.sorter.unknownHandlers, 6)
        pdu = GetBulkRequestPDU("1.2.3.4.5.6")
        msg = self.interpreter.Message(pdu).encode()

        self.assertIsNone(self.channel.data)
        self.sorter.hear(msg, self.channel)
        self.assertIsNotNone(self.channel.data)
        self.assertEqual(self.sorter.unknownHandlers, 7)

        message = self.interpreter.decode(self.channel.data)
        self.assertIsInstance(message.pdu, ReportPDU)
        self.assertEqual(len(message.pdu.variableBindings), 1)
        self.assertEqual(
            message.pdu.variableBindings[0],
            VarBind("1.3.6.1.6.3.11.2.1.3.0", Counter32(7)),
        )

    def test_ignore_exceptions_raised_by_makeReport(self):
        get_listener = self.Listener()
        get_next_listener = self.Listener()
        response_listener = self.Listener()

        self.sorter.register(GetRequestPDU, get_listener)
        self.sorter.register(GetNextRequestPDU, get_next_listener)
        self.sorter.register(ResponsePDU, response_listener)

        pdu = GetBulkRequestPDU("1.2.3.4.5.6")
        msg = self.interpreter.Message(pdu).encode()

        self.interpreter.exception = Exception()
        self.sorter.hear(msg, self.channel)
        self.assertEqual(self.sorter.unknownHandlers, 1)
        self.assertIsNone(self.channel.data)

    def test_if_decode_raises_ReportMessage_then_send_it(self):
        get_listener = self.Listener()
        get_next_listener = self.Listener()
        response_listener = self.Listener()

        self.sorter.register(GetRequestPDU, get_listener)
        self.sorter.register(GetNextRequestPDU, get_next_listener)
        self.sorter.register(ResponsePDU, response_listener)

        report = self.Interpreter.Message(
            ReportPDU((usmStatsUnknownEngineIDsInstance, Counter32(1)))
        )

        pdu = GetRequestPDU("1.3.6.1.2.1.1.1.0")
        msg = self.interpreter.Message(pdu).encode()

        self.assertIsNone(self.channel.data)
        self.interpreter.exception = ReportMessage(report)
        self.sorter.hear(msg, self.channel)
        self.assertIsNotNone(self.channel.data)
        self.assertEqual(self.sorter.unknownHandlers, 0)

        message = self.Interpreter.Message.decodeExact(self.channel.data)
        self.assertIsInstance(message.pdu, ReportPDU)
        self.assertEqual(len(message.pdu.variableBindings), 1)
        self.assertEqual(
            message.pdu.variableBindings[0],
            VarBind("1.3.6.1.6.3.15.1.1.4.0", Counter32(1)),
        )

if __name__ == "__main__":
    unittest.main()
