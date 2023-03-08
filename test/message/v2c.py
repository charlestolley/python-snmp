__all__ = ["SNMPv2cMessageProcessorTest"]

import sys
import unittest
import weakref

from snmp.ber import *
from snmp.exception import *
from snmp.message import *
from snmp.message.v2c import *
from snmp.message.v2c import pduTypes
from snmp.pdu import *
from snmp.types import *
from snmp.utils import *

class SNMPv2cMessageProcessorTest(unittest.TestCase):
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
        self.processor = SNMPv2cMessageProcessor()

        sysDescr = OctetString(b"Description of the system")
        self.pdu = SetRequestPDU(VarBind("1.3.6.1.2.1.1.0", sysDescr))
        self.response = Message(
            MessageProcessingModel.SNMPv2c,
            self.community,
            ResponsePDU(
                variableBindings=self.pdu.variableBindings,
            ),
        )

    def testRequestID(self):
        generator = NumberGenerator(1)
        _ = next(generator)

        # NOTE: relies on non-public attribute
        self.processor.generator = generator
        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.assertIsNot(self.processor.generator, generator)
        self.assertNotEqual     (self.pdu.requestID, 0)
        self.assertGreaterEqual (self.pdu.requestID, -(1<<31))
        self.assertLess         (self.pdu.requestID,  (1<<31))

    def testGenerateMessage(self):
        msg = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        message = Message.decode(msg, types=pduTypes)
        self.assertEqual(message.version, MessageProcessingModel.SNMPv2c)
        self.assertEqual(message.community, self.community)

        pdu = message.pdu
        self.assertEqual(pdu.requestID, self.pdu.requestID)
        self.assertEqual(pdu.variableBindings, self.pdu.variableBindings)

    def testAddCallback(self):
        self.assertIsNone(self.handle.callback)
        self.assertEqual(self.pdu.requestID, 0)

        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.assertIsNotNone(self.handle.callback)
        self.assertNotEqual(self.pdu.requestID, 0)
        self.assertEqual(self.handle.requestID, self.pdu.requestID)

    def testCallback(self):
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

    def testResend(self):
        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        unusedHandle = self.Handle()
        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            unusedHandle,
            self.community,
        )

        self.assertIsNone(unusedHandle.callback)
        self.assertEqual(self.handle.requestID, self.pdu.requestID)
        self.handle.callback(self.handle.requestID)

    def testHandleOwnership(self):
        refcount = sys.getrefcount(self.handle)
        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.assertEqual(sys.getrefcount(self.handle), refcount)

    def testBasicParseSanity(self):
        version = Integer(MessageProcessingModel.SNMPv2c)
        msg = encode(SEQUENCE, version.encode() + b"meaningless garbage")
        self.assertRaises(ParseError, self.processor.prepareDataElements, msg)

    def testWrongCommunity(self):
        _ = self.processor.prepareOutgoingMessage(
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

    def testValidResponse(self):
        _ = self.processor.prepareOutgoingMessage(
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

    def testDanglingHandle(self):
        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.response.pdu.requestID = self.pdu.requestID
        _, handle = self.processor.prepareDataElements(self.response.encode())

        handle = weakref.ref(self.handle)
        self.handle = None

        if handle() is not None:
            self.skipTest("handle was not immediately destroyed")

        self.assertRaises(
            IncomingMessageError,
            self.processor.prepareDataElements,
            self.response.encode(),
        )

    def testDuplicateResponse(self):
        _ = self.processor.prepareOutgoingMessage(
            self.pdu,
            self.handle,
            self.community,
        )

        self.response.pdu.requestID = self.pdu.requestID
        message, handle = self.processor.prepareDataElements(
            self.response.encode(),
        )

        handle.callback(self.handle.requestID)
        self.assertRaises(
            IncomingMessageError,
            self.processor.prepareDataElements,
            self.response.encode(),
        )

if __name__ == "__main__":
    unittest.main()
