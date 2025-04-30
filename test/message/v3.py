__all__ = ["SNMPv3MessageProcessorTest"]

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
from snmp.v3.message import *

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

        reportable = self.security.response.header.flags.reportableFlag
        flags = MessageFlags(noAuthNoPriv, reportable=reportable)
        self.security.response.header.flags = flags

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

        reportable = self.security.report.header.flags.reportableFlag
        flags = MessageFlags(noAuthNoPriv, reportable=reportable)
        self.security.response.header.flags = flags

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

        self.security.response.scopedPDU = ScopedPDU(
            self.security.response.scopedPDU.pdu,
            contextEngineID=b"",
            contextName=self.security.response.scopedPDU.contextName,
        )

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

        self.security.response.scopedPDU = ScopedPDU(
            self.security.response.scopedPDU.pdu,
            contextEngineID=self.security.response.scopedPDU.contextEngineID,
            contextName=b"",
        )

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
