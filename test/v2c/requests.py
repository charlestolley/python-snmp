__all__ = ["SNMPv2cRequestAdminTest", "SNMPv2cRequestHandleTest"]

import gc
import unittest

from snmp.exception import *
from snmp.smi import *
from snmp.pdu import *
from snmp.message import *
from snmp.scheduler import *
from snmp.v2c.requests import *
from snmp.v2c.requests import SNMPv2cRequestHandle, pduTypes

class SleepFunction:
    def __init__(self, timeFunction):
        self.timeFunction = timeFunction

    def __call__(self, delay):
        self.timeFunction.advance(delay)

class TimeFunction:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, delay):
        self.now += delay

class SNMPv2cRequestHandleTest(unittest.TestCase):
    class DelayTask(SchedulerTask):
        def run(self):
            return self

    class Callback:
        def __init__(self):
            self.requestID = None

        def __call__(self, requestID):
            self.requestID = requestID

    def setUp(self):
        self.time = TimeFunction()
        self.sleep = SleepFunction(self.time)
        self.scheduler = Scheduler(self.sleep, self.time)

        self.oid = OID(1, 3, 6, 1, 2, 1, 1, 1, 0)
        self.requestID = 0x01234567
        self.request = GetRequestPDU(self.oid, requestID=self.requestID)
        self.response = ResponsePDU(
            VarBind(
                self.oid,
                OctetString(b"system description"),
            ),
        )

        self.handle = SNMPv2cRequestHandle(self.scheduler, self.request)

    def test_handle_calls_callback_upon_receiving_a_response(self):
        response = self.response.withRequestID(69)
        msg = Message(ProtocolVersion.SNMPv2c, b"public", response)

        callback = self.Callback()
        self.handle.addCallback(callback, 69)
        self.assertIsNone(callback.requestID)
        self.handle.push(msg)
        self.assertEqual(callback.requestID, 69)

    def test_handle_calls_callback_when_request_expires(self):
        callback = self.Callback()
        self.handle.addCallback(callback, 80)

        self.assertIsNone(callback.requestID)
        self.handle.expired = True
        self.assertTrue(self.handle.expired)
        self.assertEqual(callback.requestID, 80)

    def test_handle_calls_callback_before_object_is_finalized(self):
        callback = self.Callback()
        self.handle.addCallback(callback, 89)
        self.assertIsNone(callback.requestID)

        del self.handle
        gc.collect()

        self.assertTrue(callback.requestID, 89)

    def test_multiple_callbacks_are_called_in_reverse_order(self):
        c1 = self.Callback()
        c2 = self.Callback()

        def callback_function(requestID):
            self.assertIsNone(c1.requestID)
            c2(requestID)

        self.handle.addCallback(c1, 112)
        self.handle.addCallback(callback_function, 112)

        self.assertIsNone(c2.requestID)
        self.handle.expired = True
        self.assertEqual(c1.requestID, 112)
        self.assertEqual(c2.requestID, 112)

    def test_callback_added_after_expiration_is_called_immediately(self):
        self.handle.expired = True
        callback = self.Callback()

        self.assertIsNone(callback.requestID)
        self.handle.addCallback(callback, 125)
        self.assertEqual(callback.requestID, 125)

class SNMPv2cRequestAdminTest(unittest.TestCase):
    class Channel:
        def __init__(self):
            self.requestID = None

        def send(self, data):
            message = Message.decodeExact(data, types=pduTypes)
            self.requestID = message.pdu.requestID

    def setUp(self):
        self.time = TimeFunction()
        self.sleep = SleepFunction(self.time)
        self.scheduler = Scheduler(self.sleep, self.time)
        self.admin = SNMPv2cRequestAdmin(self.scheduler)

        self.oid = "1.3.6.1.2.1.1.1.0"
        self.request = GetRequestPDU(self.oid)

        value = OctetString(b"description of the system")
        self.response = ResponsePDU(VarBind(self.oid, value))

    def test_hear_unknown_request_ID_raises_IncomingMessageError(self):
        response = self.response.withRequestID(133)
        message = Message(ProtocolVersion.SNMPv2c, b"public", response)

        self.assertRaisesRegex(
            IncomingMessageError,
            "[Rr]equest\s*ID",
            self.admin.hear,
            message.encode(),
            None,
        )

    def test_hear_wrong_community_name_raises_IncomingMessageError(self):
        channel = self.Channel()
        handle = self.admin.openRequest(
            self.request,
            b"the right community name",
            channel,
            10.0,
            1.0,
        )

        self.assertIsNotNone(channel.requestID)

        message = Message(
            ProtocolVersion.SNMPv2c,
            b"the wrong community name",
            self.response.withRequestID(channel.requestID),
        )

        self.assertRaisesRegex(
            IncomingMessageError,
            "[Cc]ommunity",
            self.admin.hear,
            message.encode(),
            None,
        )

if __name__ == "__main__":
    unittest.main()
