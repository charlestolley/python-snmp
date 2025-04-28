__all__ = ["SNMPv1RequestHandleTest"]

import unittest
import weakref

from snmp.smi import *
from snmp.pdu import *
from snmp.message import *
from snmp.scheduler import *
from snmp.v1.requests import SNMPv1RequestHandle

class SNMPv1RequestHandleTest(unittest.TestCase):
    class DelayTask(SchedulerTask):
        def run(self):
            return self

    class SleepFunction:
        def __init__(self, timeFunction):
            self.timeFunction = timeFunction
            self.response = None
            self.handle = None

        def __call__(self, delay):
            self.timeFunction.advance(delay)

            if self.handle is not None:
                self.handle.push(self.response)
                self.response = None
                self.handle = None

        def respondWhenCalled(self, handle, response):
            self.handle = handle
            self.response = response

    class TimeFunction:
        def __init__(self):
            self.now = 0.0

        def __call__(self):
            return self.now

        def advance(self, delay):
            self.now += delay

    class Callback:
        def __init__(self):
            self.requestID = None

        def __call__(self, requestID):
            self.requestID = requestID

    def setUp(self):
        self.time = self.TimeFunction()
        self.sleep = self.SleepFunction(self.time)
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

        self.handle = SNMPv1RequestHandle(self.scheduler, self.request)

    def test_handle_calls_callback_upon_receiving_a_response(self):
        response = self.response.withRequestID(69)
        msg = Message(ProtocolVersion.SNMPv1, b"public", response)

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

        canary = self.Callback()
        reference = weakref.ref(self.handle)
        canary_reference = weakref.ref(canary)

        del canary
        if canary_reference() is not None:
            self.skipTest("Canary object was not immediately destroyed")

        self.assertIsNone(callback.requestID)
        del self.handle
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

if __name__ == "__main__":
    unittest.main()
