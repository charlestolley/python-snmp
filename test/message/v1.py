__all__ = ["SNMPv1MessageProcessorTest"]

import random
import sys
import unittest
import weakref

from snmp.ber import *
from snmp.exception import *
from snmp.message import *
from snmp.message.v1 import *
from snmp.message.v1 import pduTypes
from snmp.pdu import *
from snmp.smi import *
from snmp.utils import *

class SNMPv1MessageProcessorTest(unittest.TestCase):
    class Handle(RequestHandle):
        def __init__(self):
            self.callback = None
            self.requestID = 0

        def addCallback(self, func, idNum):
            self.callback = func
            self.requestID = idNum

        def push(self, response):
            pass

    def setUp(self):
        self.community = b"testCommunity"
        self.handle = self.Handle()
        self.processor = SNMPv1MessageProcessor()

        sysDescr = OctetString(b"Description of the system")
        self.pdu = SetRequestPDU(VarBind("1.3.6.1.2.1.1.0", sysDescr))
        self.response = Message(
            ProtocolVersion.SNMPv1,
            self.community,
            ResponsePDU(
                variableBindings=self.pdu.variableBindings,
            ),
        )

    def test_prepareOutgoingMessage_sets_pdu_requestID_if_zero(self):
        self.assertEqual(self.pdu.requestID, 0)
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"")
        self.assertNotEqual(self.pdu.requestID, 0)

    def test_pOM_does_not_set_pdu_requestID_if_nonzero(self):
        requestID = random.randint(1, (1 << 31) - 1)
        self.pdu.requestID = requestID
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"")
        self.assertEqual(self.pdu.requestID, requestID)

    # NOTE: depends on the private "generator" attribute
    def test_prepareOutgoingMessage_replaces_generator_when_it_reaches_0(self):
        generator = NumberGenerator(1)
        _ = next(generator)

        self.processor.generator = generator
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"")

        self.assertIsNot(self.processor.generator, generator)
        self.assertNotEqual     (self.pdu.requestID, 0)
        self.assertGreaterEqual (self.pdu.requestID, -(1<<31))
        self.assertLess         (self.pdu.requestID,  (1<<31))

    def test_prepareOutgoingMessage_returns_encoded_message(self):
        msg = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        message = Message.decode(msg, types=pduTypes)
        self.assertEqual(message.version, ProtocolVersion.SNMPv1)
        self.assertEqual(message.community, self.community)

        pdu = message.pdu
        self.assertEqual(pdu.requestID, self.pdu.requestID)
        self.assertEqual(pdu.variableBindings, self.pdu.variableBindings)

    def test_prepareOutgoingMessage_adds_callback_if_pdu_requestID_is_0(self):
        self.assertEqual(self.pdu.requestID, 0)
        self.assertIsNone(self.handle.callback)

        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"")

        self.assertIsNotNone(self.handle.callback)
        self.assertEqual(self.handle.requestID, self.pdu.requestID)

    def test_pOM_does_not_add_callback_if_pdu_requestID_is_nonzero(self):
        self.pdu.requestID = 1
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"")
        self.assertIsNone(self.handle.callback)

    def test_handle_callback_uncaches_request(self):
        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.handle.callback(self.handle.requestID)

        self.response.pdu.requestID = self.pdu.requestID
        self.assertRaisesRegex(
            IncomingMessageError,
            "requestID",
            self.processor.prepareDataElements,
            self.response.encode(),
        )

    def test_pOM_does_not_store_a_strong_reference_to_the_handle(self):
        refcount = sys.getrefcount(self.handle)
        self.processor.prepareOutgoingMessage(self.pdu, self.handle, b"")
        self.assertEqual(sys.getrefcount(self.handle), refcount)

    # NOTE: depends on the private "generator" attribute
    def test_pOM_raises_SNMPException_if_no_cache_slot_found(self):
        n = 1000
        self.processor.generator = iter(range(n, 0, -1))

        handles = list()
        for i in range(n):
            pdu = GetRequestPDU(self.pdu.variableBindings[0].name)
            handles.append(self.Handle())
            self.processor.prepareOutgoingMessage(pdu, handles[-1], b"")

        self.processor.generator = iter(range(n, 0, -1))
        self.assertRaises(
            SNMPException,
            self.processor.prepareOutgoingMessage,
            self.pdu,
            self.handle,
            b"",
        )

    def test_prepareDataElements_raises_ParseError_on_invalid_message(self):
        version = Integer(ProtocolVersion.SNMPv1)
        msg = encode(Sequence.TAG, version.encode() + b"meaningless garbage")
        self.assertRaises(ParseError, self.processor.prepareDataElements, msg)

    def test_pDE_returns_decoded_message_with_the_correct_handle(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.response.pdu.requestID = self.pdu.requestID
        message, handle = self.processor.prepareDataElements(
            self.response.encode(),
        )

        self.assertEqual(message, self.response)
        self.assertIs(handle, self.handle)

    def test_pDE_raises_IncomingMessageError_if_community_does_not_match(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.response.pdu.requestID = self.pdu.requestID
        self.response.community = b"wrongCommunity"
        self.assertRaisesRegex(
            IncomingMessageError,
            "[Cc]ommunity",
            self.processor.prepareDataElements,
            self.response.encode(),
        )

    def test_pDE_raises_IncomingMessageError_after_handle_callback(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.handle.callback(self.handle.requestID)
        self.response.pdu.requestID = self.pdu.requestID

        self.assertRaises(
            IncomingMessageError,
            self.processor.prepareDataElements,
            self.response.encode(),
        )

    def test_pDE_raises_IncomingMessageError_if_handle_is_destroyed(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        handle = weakref.ref(self.handle)
        self.handle = None

        if handle() is not None:
            self.skipTest("handle was not immediately destroyed")

        self.response.pdu.requestID = self.pdu.requestID

        self.assertRaises(
            IncomingMessageError,
            self.processor.prepareDataElements,
            self.response.encode(),
        )

    # NOTE: depends on the private "retrieve()" method
    def test_pDE_uncaches_request_if_handle_is_destroyed(self):
        self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        handle = weakref.ref(self.handle)
        self.handle = None

        if handle() is not None:
            self.skipTest("handle was not immediately destroyed")

        self.response.pdu.requestID = self.pdu.requestID
        self.processor.retrieve(self.pdu.requestID)

        try:
            self.processor.prepareDataElements(self.response.encode())
        except IncomingMessageError:
            pass

        self.assertRaises(
            KeyError,
            self.processor.retrieve,
            self.pdu.requestID,
        )

if __name__ == "__main__":
    unittest.main()
