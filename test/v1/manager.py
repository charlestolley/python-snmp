__all__ = ["SNMPv1ManagerTest"]

import gc
import unittest
import weakref

from snmp.message import *
from snmp.pdu import *
from snmp.requests import Timeout
from snmp.scheduler import *
from snmp.smi import *
from snmp.v1.manager import *
from snmp.v1.requests import *
from snmp.v1.requests import pduTypes

class SNMPv1ManagerTest(unittest.TestCase):
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

    class Channel:
        def __init__(self, listener=None):
            self.messages = []

            self.listener = listener
            self.response = None
            self.msgCount = 0
            self.called = False

        def callback(self, requestID):
            self.called = True

        def scheduleResponse(self, response, msgCount = 1):
            self.response = response
            self.msgCount = msgCount

        def send(self, data):
            msg = Message.decodeExact(data, types=pduTypes)
            self.messages.append(msg)

            if self.response is not None:
                if len(self.messages) == self.msgCount:
                    response = self.response.withRequestID(msg.pdu.requestID)
                    message = Message(msg.version, msg.community, response)

                    if self.listener is not None:
                        self.listener.hear(message.encode(), None)

                    self.response = None
                    self.msgCount = 0

    def setUp(self):
        self.time = self.TimeFunction()
        self.sleep = self.SleepFunction(self.time)

        self.scheduler = Scheduler(self.sleep, self.time)
        self.admin = SNMPv1RequestAdmin(self.scheduler)
        self.channel = self.Channel(self.admin)
        self.community = b"default community string"

        self.manager = SNMPv1Manager(self.admin, self.channel, self.community)

        self.oid = OID(1, 3, 6, 1, 2, 1, 1, 1, 0)
        self.response = ResponsePDU(
            VarBind(
                self.oid,
                OctetString(b"system description"),
            ),
        )

    def test_empty_request_is_sent_immediately(self):
        self.channel.scheduleResponse(ResponsePDU())

        vblist = self.manager.get()
        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, VarBindList())

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, GetRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 0)

    def test_single_OID_request_is_sent_immediately(self):
        self.channel.scheduleResponse(self.response)

        vblist = self.manager.get(self.oid)
        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, self.response.variableBindings)

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, GetRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, self.oid)
        self.assertEqual(pdu.variableBindings[0].value, Null())

    def test_three_OID_request_is_sent_immediately(self):
        first = OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)
        third = OID(1, 2, 3, 4, 5, 6)

        response = ResponsePDU(
            VarBind(first, OctetString(b"interface number 1")),
            VarBind(self.oid, OctetString(b"system description")),
            VarBind(third, Integer(123456)),
        )

        self.channel.scheduleResponse(response)

        vblist = self.manager.get(first, self.oid, third)
        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, response.variableBindings)

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, GetRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 3)

        self.assertEqual(pdu.variableBindings[0].name, first)
        self.assertEqual(pdu.variableBindings[1].name, self.oid)
        self.assertEqual(pdu.variableBindings[2].name, third)

    def test_OID_strings_are_automatically_parsed(self):
        first = "1.3.6.1.2.1.2.2.1.2.1"
        third = "1.2.3.4.5.6"

        handle = self.manager.get(first, self.oid, third, wait=False)
        self.assertEqual(len(self.channel.messages), 1)
        pdu = self.channel.messages[0].pdu
        self.assertEqual(len(pdu.variableBindings), 3)

        self.assertEqual(pdu.variableBindings[0].name, OID.parse(first))
        self.assertEqual(pdu.variableBindings[1].name, self.oid)
        self.assertEqual(pdu.variableBindings[2].name, OID.parse(third))

    def test_request_uses_default_community_string(self):
        handle = self.manager.get(self.oid, wait=False)
        self.assertEqual(len(self.channel.messages), 1)
        community = self.channel.messages[0].community
        self.assertEqual(community, self.community)

    def test_request_uses_provided_community_string(self):
        community = b"different community string than usual"
        vblist = self.manager.get(self.oid, community=community, wait=False)

        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.channel.messages[0].community, community)

    def test_request_without_a_response_raises_Timeout(self):
        self.assertRaises(Timeout, self.manager.get, self.oid)

    def test_request_expires_after_timeout_seconds(self):
        self.assertRaises(Timeout, self.manager.get, self.oid, timeout=3.5)
        self.assertEqual(self.time(), 3.5)

    def test_request_resends_after_refreshPeriod_seconds(self):
        self.channel.scheduleResponse(self.response, 2)
        vblist = self.manager.get(self.oid, refreshPeriod=0.25)
        self.assertEqual(self.time(), 0.25)

    def test_request_resends_every_refreshPeriod_seconds(self):
        self.channel.scheduleResponse(self.response, 5)
        vblist = self.manager.get(self.oid, refreshPeriod=0.75)
        self.assertEqual(self.time(), 3.0)

    def test_request_stops_resending_after_response_arrives(self):
        self.channel.scheduleResponse(self.response, 5)
        handle = self.manager.get(
            self.oid,
            timeout=5.0,
            refreshPeriod=0.75,
            wait=False,
        )

        self.scheduler.schedule(self.DelayTask(), 7.0)
        while self.time() < 7.0:
            self.scheduler.wait()

        self.assertEqual(len(self.channel.messages), 5)

    def test_ValueError_if_refreshPeriod_is_zero(self):
        self.assertRaises(ValueError, self.manager.get, refreshPeriod=0.0)

    def test_ValueError_if_refreshPeriod_is_negative(self):
        self.assertRaises(ValueError, self.manager.get, refreshPeriod=-0.5)

    def test_request_is_not_sent_if_timeout_is_zero(self):
        self.assertRaises(Timeout, self.manager.get, timeout=0.0)
        self.assertEqual(len(self.channel.messages), 0)
        self.assertEqual(self.time(), 0)

    def test_request_is_not_sent_if_timeout_is_negative(self):
        self.assertRaises(Timeout, self.manager.get, timeout=-0.5)
        self.assertEqual(len(self.channel.messages), 0)
        self.assertEqual(self.time(), 0)

    def test_error_status_is_raised_as_ErrorResponse(self):
        response = ResponsePDU(
            VarBind(self.oid, Null()),
            errorStatus = ErrorStatus.tooBig,
            errorIndex = 1,
        )

        self.channel.scheduleResponse(response)
        self.assertRaises(ErrorResponse, self.manager.get, self.oid)

    def test_return_handle_when_wait_is_False(self):
        self.channel.scheduleResponse(self.response)
        handle = self.manager.get(self.oid, wait=False)
        vblist = handle.wait()

        self.assertEqual(vblist, self.response.variableBindings)

    def test_handle_wait_blocks_until_response_arrives(self):
        self.channel.scheduleResponse(self.response, 3)
        handle = self.manager.get(self.oid, wait=False)
        vblist = handle.wait()

        self.assertEqual(self.time(), 2.0)

    def test_handle_returns_immediately_if_response_is_ready(self):
        self.channel.scheduleResponse(self.response, 5)
        handle = self.manager.get(self.oid, wait=False)

        self.scheduler.schedule(self.DelayTask(), 6.0)

        while self.time() < 6.0:
            self.scheduler.wait()

        self.assertEqual(self.time(), 6.0)
        vblist = handle.wait()
        self.assertEqual(self.time(), 6.0)

    def test_response_arrives_before_timeout_if_handle_is_never_touched(self):
        """This test simulates a case where the user sends a request, but
        does not give the scheduler a chance to run until after the timeout
        for the request has been passed. This tests that the handle does not
        expire until it has given the scheduler a chance to run, and that the
        scheduler does not run any tasks until the incoming messages have been
        pushed to the handles that are awaiting them.
        """
        handle = self.manager.get(self.oid, wait=False)

        response = Message(
            ProtocolVersion.SNMPv1,
            self.community,
            ResponsePDU(
                VarBind(self.oid, OctetString(b"system description")),
                requestID = self.channel.messages[0].pdu.requestID,
            )
        )

        self.sleep.respondWhenCalled(handle, response)
        self.time.advance(12.0)

        self.assertEqual(self.time(), 12.0)
        vblist = handle.wait()
        self.assertEqual(self.time(), 12.0)
        self.assertEqual(vblist, response.pdu.variableBindings)

    def test_response_ignored_after_handle_has_expired(self):
        handle = self.manager.get(self.oid, timeout=2.0, wait=False)

        self.assertRaises(
            Timeout,
            self.manager.get,
            "1.2.3.4.5.6",
            timeout=3.0,
        ) 

        self.response.requestID = self.channel.messages[0].pdu.requestID
        msg = Message(ProtocolVersion.SNMPv1, self.community, self.response)
        handle.push(msg)

        self.assertRaises(Timeout, handle.wait)

    def test_multiple_calls_to_wait_raise_Timeout(self):
        handle = self.manager.get(self.oid, wait=False)
        self.assertRaises(Timeout, handle.wait)
        self.assertRaises(Timeout, handle.wait)

    def test_multiple_calls_to_wait_return_the_same_result(self):
        self.channel.scheduleResponse(self.response)
        handle = self.manager.get(self.oid, wait=False)
        vbl1 = handle.wait()
        vbl2 = handle.wait()

        self.assertEqual(vbl1, vbl2)

    def test_multiple_calls_to_wait_raise_ErrorResponse(self):
        response = ResponsePDU(
            VarBind(self.oid, Null()),
            errorStatus = ErrorStatus.tooBig,
            errorIndex = 1,
        )

        self.channel.scheduleResponse(response)
        handle = self.manager.get(self.oid, wait=False)
        self.assertRaises(ErrorResponse, handle.wait)
        self.assertRaises(ErrorResponse, handle.wait)

    def test_wait_still_returns_response_long_after_first_call(self):
        self.channel.scheduleResponse(self.response)
        handle = self.manager.get(self.oid, timeout=5.0, wait=False)

        vbl1 = handle.wait()
        self.assertEqual(self.time(), 0.0)

        self.time.advance(6.0)
        vbl2 = handle.wait()
        self.assertEqual(vbl1, vbl2)

    def test_no_more_resends_after_handle_is_dropped(self):
        handle = self.manager.get(self.oid, wait=False)
        reference = weakref.ref(handle)

        self.scheduler.schedule(self.DelayTask(), 1.5)
        self.scheduler.schedule(self.DelayTask(), 10.0)

        while self.time() < 1.5:
            self.scheduler.wait()

        self.assertEqual(len(self.channel.messages), 2)

        del handle
        gc.collect()

        while self.time() < 10.0:
            self.scheduler.wait()

        self.assertEqual(len(self.channel.messages), 2)

    def test_getBulk_with_maxRepetitions_0_omits_repeaters(self):
        self.channel.scheduleResponse(self.response)

        oid = OID(*self.oid[:-1])
        vblist = self.manager.getBulk(
            oid,
            "1.3.6.1.2.1.2.2.1.1",
            "1.3.6.1.2.1.2.2.1.2",
            nonRepeaters=1,
            maxRepetitions=0,
        )

        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, self.response.variableBindings)

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, GetNextRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, oid)
        self.assertEqual(pdu.variableBindings[0].value, Null())

    def test_getBulk_with_maxRepetitions_1_send_GetNextRequestPDU(self):
        self.channel.scheduleResponse(self.response)

        oid = OID(*self.oid[:-1])
        vblist = self.manager.getBulk(oid)
        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, self.response.variableBindings)

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, GetNextRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, oid)
        self.assertEqual(pdu.variableBindings[0].value, Null())

    def test_getBulk_with_maxRepetitions_2_sends_GetNextRequestPDU(self):
        self.channel.scheduleResponse(self.response)

        oid = OID(*self.oid[:-1])
        vblist = self.manager.getBulk(oid, maxRepetitions=2)
        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, self.response.variableBindings)

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, GetNextRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, oid)
        self.assertEqual(pdu.variableBindings[0].value, Null())

    def test_getNext_sends_GetNextRequestPDU(self):
        self.channel.scheduleResponse(self.response)

        oid = OID(*self.oid[:-1])
        vblist = self.manager.getNext(oid)
        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, self.response.variableBindings)

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, GetNextRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, oid)
        self.assertEqual(pdu.variableBindings[0].value, Null())

    def test_set_sends_SetRequestPDU(self):
        value = OctetString(b"updated system description")
        response = ResponsePDU(VarBind(self.oid, value))
        self.channel.scheduleResponse(response)

        vblist = self.manager.set((self.oid, value))
        self.assertEqual(len(self.channel.messages), 1)
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(vblist, response.variableBindings)

        pdu = self.channel.messages[0].pdu
        self.assertIsInstance(pdu, SetRequestPDU)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, self.oid)
        self.assertEqual(pdu.variableBindings[0].value, value)

if __name__ == "__main__":
    unittest.main()
