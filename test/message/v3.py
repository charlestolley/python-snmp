__all__ = [
    "HeaderDataTest", "MessageFlagsTest", "ScopedPDUTest",
    "SNMPv3MessageTest", "SNMPv3MessageProcessorTest",
]

import re
import sys
import unittest
import weakref

from snmp.ber import *
from snmp.exception import *
from snmp.message import *
from snmp.message.v3 import *
from snmp.message.v3 import UnknownSecurityModel, pduTypes
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.smi import *
from snmp.utils import *

class MessageFlagsTest(unittest.TestCase):
    def test_auth_priv_and_reportable_flags_are_off_by_default(self):
        flags = MessageFlags()
        self.assertFalse(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def test_two_objects_with_identical_flags_are_equal(self):
        self.assertEqual(
            MessageFlags(authNoPriv, True),
            MessageFlags(authNoPriv, True),
        )

    def test_two_objects_with_different_flags_are_not_equal(self):
        self.assertNotEqual(MessageFlags(authPriv), MessageFlags(authNoPriv))

    def test_securityLevel_parameter_initializes_auth_and_priv_flags(self):
        for level in (noAuthNoPriv, authNoPriv, authPriv):
            flags = MessageFlags(level)
            self.assertEqual(level.auth, flags.authFlag)
            self.assertEqual(level.priv, flags.privFlag)

    def test_reportable_parameter_initializes_reportableFlag(self):
        for reportable in (False, True):
            flags = MessageFlags(reportable=reportable)
            self.assertEqual(reportable, flags.reportableFlag)

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        test_cases = (
            MessageFlags(authPriv, False),
            MessageFlags(authNoPriv, True),
            MessageFlags(reportable=True)
        )

        for flags in test_cases:
            self.assertEqual(eval(repr(flags)), flags)

    def test_decode_raises_ParseError_on_empty_string(self):
        self.assertRaises(ParseError, MessageFlags.decode, b"\x04\x00")

    def test_decode_raises_IncomingMessageError_on_invalid_securityLevel(self):
        self.assertRaises(
            IncomingMessageError,
            MessageFlags.decode,
            b"\x04\x01\x02",
        )

    def test_decode_sets_each_flag_based_on_the_correct_bit(self):
        test_cases = (
            (b"\x04\x01\x01", MessageFlags(authNoPriv)),
            (b"\x04\x01\x03", MessageFlags(authPriv)),
            (b"\x04\x01\x04", MessageFlags(reportable=True)),
            (b"\x04\x01\x07", MessageFlags(authPriv, True)),
        )

        for encoding, flags in test_cases:
            self.assertEqual(MessageFlags.decode(encoding), flags)

    def test_decode_ignores_extra_bytes(self):
        self.assertEqual(
            MessageFlags.decode(b"\x04\x02\x07\x00"),
            MessageFlags(authPriv, True),
        )

    def test_decode_ignores_extra_bits(self):
        self.assertEqual(
            MessageFlags.decode(b"\x04\x01\x09"),
            MessageFlags(authNoPriv),
        )

    def test_authFlag_is_assignable(self):
        flags = MessageFlags()
        flags.authFlag = True
        self.assertTrue(flags.authFlag)
        flags.authFlag = False
        self.assertFalse(flags.authFlag)

    def test_privFlag_is_assignable(self):
        flags = MessageFlags(authNoPriv)
        flags.privFlag = True
        self.assertTrue(flags.privFlag)
        flags.privFlag = False
        self.assertFalse(flags.privFlag)

    def test_reportableFlag_is_assignable(self):
        flags = MessageFlags()
        flags.reportableFlag = True
        self.assertTrue(flags.reportableFlag)
        flags.reportableFlag = False
        self.assertFalse(flags.reportableFlag)

    def test_authFlag_setter_raises_ValueError_for_invalid_securityLevel(self):
        def assignAuthFlag(flags, auth):
            flags.authFlag = auth

        flags = MessageFlags(authPriv)
        self.assertRaises(ValueError, assignAuthFlag, flags, False)

    def test_privFlag_setter_raises_ValueError_for_invalid_securityLevel(self):
        def assignPrivFlag(flags, priv):
            flags.privFlag = priv

        flags = MessageFlags()
        self.assertRaises(ValueError, assignPrivFlag, flags, True)

class HeaderDataTest(unittest.TestCase):
    def setUp(self):
        self.encoding = bytes.fromhex(re.sub(r"\n", "", """
            30 10
               02 04 17 39 27 45
               02 02 05 dc
               04 01 07
               02 01 03
        """))

        self.header = HeaderData(
            0x17392745,
            1500,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

    def test_decode_raises_ParseError_if_msgID_is_negative(self):
        valid   = bytes.fromhex("3010020400000000020205dc040107020103")
        invalid = bytes.fromhex("30100204ffffffff020205dc040107020103")

        _ = HeaderData.decode(valid)
        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_ParseError_if_msgID_is_too_large(self):
        valid   = bytes.fromhex("30110205007fffffff020205dc040107020103")
        invalid = bytes.fromhex("301102050080000000020205dc040107020103")

        _ = HeaderData.decode(valid)
        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_ParseError_if_msgMaxSize_is_below_484(self):
        valid   = bytes.fromhex("300d020100020201e4040107020103")
        invalid = bytes.fromhex("300d020100020201e3040107020103")

        _ = HeaderData.decode(valid)
        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_ParseError_if_msgMaxSize_is_too_large(self):
        valid   = bytes.fromhex("30100201000205007fffffff040107020103")
        invalid = bytes.fromhex("301002010002050080000000040107020103")

        _ = HeaderData.decode(valid)
        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_example_matches_the_hand_computed_result(self):
        self.assertEqual(HeaderData.decode(self.encoding), self.header)

    def test_encode_example_matches_the_hand_computed_result(self):
        self.assertEqual(self.header.encode(), self.encoding)

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        self.assertEqual(eval(repr(self.header)), self.header)

class ScopedPDUTest(unittest.TestCase):
    def setUp(self):
        self.encoding = bytes.fromhex(re.sub(r"\n", "", """
            30 57
               04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
               04 0b 73 6f 6d 65 43 6f 6e 74 65 78 74
               a2 3a
                  02 04 f9 6b fa c3
                  02 01 00
                  02 01 00
                  30 2c
                     30 2a
                        06 07 2b 06 01 02 01 01 00
                        04 1f 54 68 69 73 20 73 74 72 69 6e 67 20 64 65 73
                           63 72 69 62 65 73 20 6d 79 20 73 79 73 74 65 6d
        """))

        self.scopedPDU = ScopedPDU(
            ResponsePDU(
                requestID=-110363965,
                variableBindings=VarBindList(
                    VarBind(
                        "1.3.6.1.2.1.1.0",
                        OctetString(b"This string describes my system"),
                    )
                )
            ),
            b"someEngineID",
            b"someContext",
        )

    def test_decode_raises_ParseError_if_PDU_tag_is_not_in_types(self):
        self.assertRaises(
            ParseError,
            ScopedPDU.decode,
            self.encoding,
            types={},
        )

    def test_decode_example_matches_the_hand_computed_result(self):
        scopedPDU = ScopedPDU.decode(self.encoding, types=pduTypes)
        self.assertEqual(scopedPDU, self.scopedPDU)

    def test_encode_example_matches_the_hand_computed_result(self):
        self.assertEqual(self.scopedPDU.encode(), self.encoding)

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        self.assertEqual(eval(repr(self.scopedPDU)), self.scopedPDU)

class SNMPv3MessageTest(unittest.TestCase):
    def setUp(self):
        self.plain = bytes.fromhex(re.sub(r"\n", "", """
            30 81 96
               02 01 03
               30 10
                  02 04 35 b8 30 e4
                  02 02 05 dc
                  04 01 00
                  02 01 03
               04 26
                  30 24
                     04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                     02 01 66
                     02 03 11 d7 6d
                     04 08 73 6f 6d 65 55 73 65 72
                     04 00
                     04 00
               30 57
                  04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                  04 0b 73 6f 6d 65 43 6f 6e 74 65 78 74
                  a2 3a
                     02 04 f9 6b fa c3
                     02 01 00
                     02 01 00
                     30 2c
                        30 2a
                           06 07 2b 06 01 02 01 01 00
                           04 1f 54 68 69 73 20 73 74 72 69 6e 67 20 64 65 73
                              63 72 69 62 65 73 20 6d 79 20 73 79 73 74 65 6d
        """))

        self.encrypted = bytes.fromhex(re.sub("\n", "", """
            30 55
               02 01 03
               30 10
                  02 04 6f 10 97 b5
                  02 02 05 dc
                  04 01 03
                  02 01 03
               04 26
                  30 24
                     04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                     02 01 66
                     02 03 11 d7 6d
                     04 08 73 6f 6d 65 55 73 65 72
                     04 00
                     04 00
               04 16 54 68 69 73 20 64 61 74 61 20 69
                     73 20 65 6e 63 72 79 70 74 65 64
        """))

        self.plainMessage = SNMPv3Message(
            HeaderData(
                0x35b830e4,
                1500,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ResponsePDU(
                    requestID=-110363965,
                    variableBindings=VarBindList(
                        VarBind(
                            "1.3.6.1.2.1.1.0",
                            OctetString(b"This string describes my system"),
                        )
                    )
                ),
                b"someEngineID",
                b"someContext",
            ),
            securityParameters = OctetString(
                bytes.fromhex(re.sub(r"\n", "", """
                    30 24
                       04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                       02 01 66
                       02 03 11 d7 6d
                       04 08 73 6f 6d 65 55 73 65 72
                       04 00
                       04 00
                """))
            ),
        )

        self.encryptedMessage = SNMPv3Message(
            HeaderData(
                0x6f1097b5,
                1500,
                MessageFlags(authPriv),
                SecurityModel.USM,
            ),
            encryptedPDU = OctetString(b"This data is encrypted"),
            securityParameters = OctetString(
                bytes.fromhex(re.sub(r"\n", "", """
                    30 24
                       04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                       02 01 66
                       02 03 11 d7 6d
                       04 08 73 6f 6d 65 55 73 65 72
                       04 00
                       04 00
                """))
            ),
        )

        self.reprMessage = SNMPv3Message(
            HeaderData(
                0x33dc831f,
                1500,
                MessageFlags(authPriv),
                SecurityModel.USM,
            ),
            encryptedPDU=OctetString(b"Just pretend this is encrypted"),
            securityParameters=OctetString(b"And pretent this is useful"),
            securityEngineID=b"This is an engine ID",
            securityName=b"This is my name",
        )

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        messages = (
            self.plainMessage,
            self.encryptedMessage,
            self.reprMessage,
        )

        for message in messages:
            self.assertEqual(eval(repr(message)), message)

    def test__str__does_not_throw_an_exception_for_these_examples(self):
        messages = (
            self.plainMessage,
            self.encryptedMessage,
            self.reprMessage,
        )

        for message in messages:
            self.assertIsInstance(str(message), str)

    def test_decode_raises_IncomingMessageError_for_bad_version(self):
        encoding = bytes.fromhex(
            "3016020102300d020100020201e404010302010304000400",
        )

        self.assertRaises(IncomingMessageError, SNMPv3Message.decode, encoding)

    def test_encode_raises_SNMPLibraryBug_for_missing_PDU_by_privFlag(self):
        if not __debug__:
            self.skipTest("__debug__ is set to False")

        plain = SNMPv3Message(
            HeaderData(0, 0, MessageFlags(authNoPriv), SecurityModel.USM),
        )

        self.assertRaisesRegex(SNMPLibraryBug, "scopedPDU", plain.encode)

        encrypted = SNMPv3Message(
            HeaderData(0, 0, MessageFlags(authPriv), SecurityModel.USM),
        )

        self.assertRaisesRegex(
            SNMPLibraryBug,
            "encryptedPDU",
            encrypted.encode,
        )

    def test_set_scopedPDU_by_assigning_encoding_to_plaintext_attribute(self):
        scopedPDU = ScopedPDU(ResponsePDU(), b"")
        message = SNMPv3Message(
            HeaderData(0, 0, MessageFlags(authPriv), SecurityModel.USM),
            encryptedPDU = OctetString(),
        )

        self.assertIsNone(message.scopedPDU)
        message.plaintext = scopedPDU.encode()
        self.assertEqual(message.scopedPDU, scopedPDU)

    def test_fSP_returns_securityParameters_as_a_subbytes_of_wholeMsg(self):
        sp = SNMPv3Message.findSecurityParameters(self.plain)
        self.assertIsInstance(sp, subbytes)
        self.assertIs(sp.data, self.plain)
        self.assertEqual(sp, self.plainMessage.securityParameters.data)

    def test_decode_does_not_set_securityEngineID_or_securityName(self):
        message = SNMPv3Message.decode(self.plain)
        self.assertIsNone(message.securityEngineID)
        self.assertIsNone(message.securityName)

    def test_example_plain_decodes_to_example_plainMessage(self):
        self.assertEqual(SNMPv3Message.decode(self.plain), self.plainMessage)

    def test_example_encrypted_decodes_to_example_encryptedMessage(self):
        self.assertEqual(
            SNMPv3Message.decode(self.encrypted),
            self.encryptedMessage,
        )

    def test_example_plainMessage_encodes_to_example_plain(self):
        self.assertEqual(self.plainMessage.encode(), self.plain)

    def test_example_encryptedMessage_encodes_to_example_encrypted(self):
        self.assertEqual(self.encryptedMessage.encode(), self.encrypted)

class SNMPv3MessageProcessorTest(unittest.TestCase):
    class SpyModule(SecurityModule[SNMPv3Message]):
        MODEL = SecurityModel.USM
        RESULT = b"this is a fake result from a fake security module"

        def __init__(self):
            self.message = None
            self.engineID = None
            self.securityName = None
            self.response = None

        def processIncoming(self, message):
            message.securityEngineID = self.engineID
            message.securityName = self.securityName

        def prepareOutgoing(self, message, engineID, securityName):
            self.message = message
            self.engineID = engineID
            self.securityName = securityName

            self.report = SNMPv3Message(
                HeaderData(
                    message.header.id,
                    message.header.maxSize,
                    MessageFlags(message.header.flags.securityLevel),
                    self.MODEL,
                ),
                scopedPDU=ScopedPDU(
                    ReportPDU(
                        VarBind("1.3.6.1.6.3.15.1.1.4.0", Integer(1)),
                    ),
                    engineID,
                ),
            )

            self.response = SNMPv3Message(
                HeaderData(
                    message.header.id,
                    message.header.maxSize,
                    MessageFlags(message.header.flags.securityLevel),
                    self.MODEL,
                ),
                ScopedPDU(
                    ResponsePDU(
                        variableBindings=message.scopedPDU.pdu.variableBindings
                    ),
                    engineID,
                ),
            )

            return self.RESULT

    class FakeSecurityModule(SecurityModule[SNMPv3Message]):
        MODEL = 0

    class Handle(RequestHandle):
        def __init__(self):
            self.callback = None
            self.msgID = 0

        def addCallback(self, func, idNum):
            self.callback = func
            self.msgID = idNum

        def push(self, response):
            pass

    def setUp(self):
        self.maxMsgSize = 1472
        self.handle = self.Handle()
        self.security = self.SpyModule()
        self.processor = SNMPv3MessageProcessor(self.maxMsgSize)
        self.processor.addSecurityModuleIfNeeded(self.security)

        sysDescr = OctetString(b"Description of the system")
        self.pdu = SetRequestPDU(VarBind("1.3.6.1.2.1.1.0", sysDescr))
        self.response = ResponsePDU(variableBindings=self.pdu.variableBindings)
        self.engineID = b"I am an engine"
        self.securityName = b"someUser"
        self.contextName = b"fake context"

    def test_default_security_model_determined_by_the_first_added_module(self):
        processor = SNMPv3MessageProcessor(self.maxMsgSize)
        security = self.SpyModule()
        fake = self.FakeSecurityModule()
        self.assertNotEqual(security.MODEL, fake.MODEL)

        processor.addSecurityModuleIfNeeded(security)
        processor.addSecurityModuleIfNeeded(fake)
        self.assertEqual(processor.defaultSecurityModel, security.MODEL)

    def test_default_security_model_overridden_with_default_argument(self):
        processor = SNMPv3MessageProcessor(self.maxMsgSize)
        security = self.SpyModule()
        fake = self.FakeSecurityModule()
        self.assertNotEqual(security.MODEL, fake.MODEL)

        processor.addSecurityModuleIfNeeded(fake)
        self.assertEqual(processor.defaultSecurityModel, fake.MODEL)
        processor.addSecurityModuleIfNeeded(security, default=True)
        self.assertEqual(processor.defaultSecurityModel, security.MODEL)

    def test_only_use_the_first_added_securityModule_for_a_given_model(self):
        processor = SNMPv3MessageProcessor(self.maxMsgSize)
        sm1 = self.SpyModule()
        sm2 = self.SpyModule()

        processor.addSecurityModuleIfNeeded(sm1)
        processor.addSecurityModuleIfNeeded(sm2)
        self.assertIs(processor.securityModules[self.SpyModule.MODEL], sm1)

    # NOTE: depends on the private "generator" attribute
    def test_prepareOutgoingMessage_replaces_generator_when_it_reaches_0(self):
        generator = NumberGenerator(1)
        _ = next(generator)

        self.processor.generator = generator
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            b"",
            b"",
        )

        self.assertIsNot(self.processor.generator, generator)

        msgID = self.security.message.header.id
        self.assertGreater(msgID, 0)
        self.assertLess(msgID, (1<<31))

    def test_pOM_calls_securityModule_prepareOutgoing_and_returns_result(self):
        result = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.engineID,
            self.securityName,
        )

        self.assertEqual(result, self.security.RESULT)
        self.assertEqual(self.security.engineID, self.engineID)
        self.assertEqual(self.security.securityName, self.securityName)

    def test_prepareOutgoingMessage_adds_callback_if_pdu_is_a_request(self):
        self.assertIsNone(self.handle.callback)
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"", b"")
        self.assertIsNotNone(self.handle.callback)

    def test_pOM_does_not_add_callback_if_pdu_is_not_request(self):
        args = (self.response, self.handle, b"", b"")
        self.processor.prepareOutgoingMessage(*args)
        self.assertIsNone(self.handle.callback)

    def test_pOM_does_not_store_a_strong_reference_to_the_handle(self):
        refcount = sys.getrefcount(self.handle)
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"", b"")
        self.assertEqual(sys.getrefcount(self.handle), refcount)

    def test_pOM_only_sets_reportable_flag_if_pdu_is_a_request(self):
        args = (self.handle, b"", b"")

        self.processor.prepareOutgoingMessage(self.pdu, *args)
        self.assertTrue(self.security.message.header.flags.reportableFlag)

        self.processor.prepareOutgoingMessage(self.response, *args)
        self.assertFalse(self.security.message.header.flags.reportableFlag)

    # NOTE: depends on the private "generator" attribute
    def test_pOM_tries_multiple_times_to_find_a_cache_slot(self):
        def quadrupler(generator):
            for n in generator:
                for _ in range(4):
                    yield n

        self.processor.generator = quadrupler(self.processor.generator)
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"", b"")

        msgID = self.security.message.header.id
        handle = self.Handle()
        self.processor.prepareOutgoingMessage(self.pdu, handle, b"", b"")
        self.assertIsNotNone(handle.callback)
        self.assertNotEqual(handle.msgID, msgID)

    # NOTE: depends on the private "generator" attribute
    def test_pOM_raises_SNMPException_if_no_cache_slot_found(self):
        n = 100
        self.processor.generator = iter(range(n, 0, -1))

        handles = list()
        for i in range(n):
            pdu = GetRequestPDU(self.pdu.variableBindings[0].name)
            handles.append(self.Handle())
            self.processor.prepareOutgoingMessage(pdu, handles[-1], b"", b"")

        self.processor.generator = iter(range(n, 0, -1))
        self.assertRaises(
            SNMPException,
            self.processor.prepareOutgoingMessage,
            self.pdu,
            self.handle,
            b"",
            b"",
        )

    def test_prepareDataElements_raises_ParseError_on_invalid_message(self):
        version = Integer(ProtocolVersion.SNMPv3)
        msg = encode(Sequence.TAG, version.encode() + b"meaningless garbage")
        self.assertRaises(ParseError, self.processor.prepareDataElements, msg)

    def test_pDE_raises_UnknownSecurityModel_on_unknown_security_model(self):
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"", b"")
        self.security.response.header.securityModel += 1

        self.assertRaises(
            UnknownSecurityModel,
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_raises_IncomingMessageError_if_no_request_is_found(self):
        response = SNMPv3Message(
            HeaderData(
                0x12345678,
                self.maxMsgSize,
                MessageFlags(),
                self.security.MODEL,
            ),
            ScopedPDU(self.response, b""),
        )

        self.assertRaisesRegex(
            IncomingMessageError,
            "msgID",
            self.processor.prepareDataElements,
            response.encode(),
        )

    def test_handle_callback_uncaches_request(self):
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"", b"")
        self.handle.callback(self.handle.msgID)

        self.assertRaisesRegex(
            IncomingMessageError,
            "msgID",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_raises_IncomingMessageError_if_handle_is_destroyed(self):
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"", b"")

        handle = weakref.ref(self.handle)
        self.handle = None

        if handle() is not None:
            self.skipTest("handle was not immediately destroyed")

        self.assertRaisesRegex(
            IncomingMessageError,
            "[Hh]andle",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_IncomingMessageError_if_response_securityLevel_too_low(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.engineID,
            self.securityName,
            authNoPriv,
        )

        self.security.response.header.flags.authFlag = False
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Ss]ecurity.*[Ll]evel",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_no_error_if_report_securityLevel_too_low(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.engineID,
            self.securityName,
            authNoPriv,
        )

        self.security.report.header.flags.authFlag = False
        self.processor.prepareDataElements(self.security.report.encode())

    def test_pDE_IncomingMessageError_on_securityEngineID_mismatch(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.engineID,
            self.securityName,
        )

        self.security.engineID = b""
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Ss]ecurity.*[Ee]ngine.*[Ii][Dd]",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_no_error_on_report_securityEngineID_mismatch(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            b"",
            b"",
        )

        self.security.engineID = self.engineID
        self.processor.prepareDataElements(self.security.report.encode())

    def test_pDE_IncomingMessageError_on_contextEngineID_mismatch(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.engineID,
            self.securityName,
        )

        self.security.response.scopedPDU.contextEngineID = b""
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Cc]ontext.*[Ee]ngine.*[Ii][Dd]",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_no_error_on_report_contextEngineID_mismatch(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            b"",
            b"",
        )

        self.security.report.contextEngineID = self.engineID
        self.processor.prepareDataElements(self.security.report.encode())

    def test_pDE_IncomingMessageError_on_securityName_mismatch(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.engineID,
            self.securityName,
        )

        self.security.securityName = b""
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Ss]ecurity.*[Nn]ame",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_IncomingMessageError_on_contextName_mismatch(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.engineID,
            self.securityName,
            contextName=self.contextName,
        )

        self.security.response.scopedPDU.contextName = b""
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Cc]ontext.*[Nn]ame",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

    def test_pDE_returned_handle_has_the_same_msgID_as_the_message(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            b"",
            b"",
        )

        message, handle = self.processor.prepareDataElements(
            self.security.response.encode(),
        )

        self.assertEqual(message, self.security.response)
        self.assertEqual(message.header.id, handle.msgID)

    def test_pOM_does_not_cache_non_reportable_messages(self):
        self.processor.prepareOutgoingMessage(
            self.response,
            self.handle,
            b"",
            b"",
        )

        self.assertRaisesRegex(
            IncomingMessageError,
            "msgID",
            self.processor.prepareDataElements,
            self.security.response.encode(),
        )

if __name__ == "__main__":
    unittest.main()
