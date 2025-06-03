# TODO: Remove the 1/64 second delay from the Channel implementation
# TODO: Use a Thingy that sends the discovery reply from within the hear() method
# TODO: Check line lengths

import unittest

from snmp.exception import *
from snmp.smi import *
from snmp.pdu import *
from snmp.requests import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm.stats import *
from snmp.scheduler import *
from snmp.v3.manager import *
from snmp.v3.message import *
from snmp.v3.requests import *
from snmp.v3.manager import Thingy3, SNMPv3Manager3

class TimeFunction:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, delay):
        if delay > 0.0:
            self.now += delay

class SleepFunction:
    def __init__(self, timeFunction):
        self.timeFunction = timeFunction

    def __call__(self, delay):
        self.timeFunction.advance(delay)

class InterruptTask(SchedulerTask):
    def __init__(self):
        self.ready = False

    def run(self):
        self.ready = True

class Channel:
    class HearTask(SchedulerTask):
        def __init__(self, target, message, channel):
            self.channel = channel
            self.message = message
            self.target = target

        def run(self):
            self.target.hear(self.message, self.channel)

    def __init__(self, scheduler):
        self.scheduler = scheduler
        self.partner = None
        self.target = None

    def connect(self, target, channel):
        self.partner = channel
        self.target = target

    def send(self, message):
        if self.target is not None:
            task = self.HearTask(self.target, message, self.partner)
            self.scheduler.schedule(task)#, 1/64)

class Sender:
    def send(self, message, channel):
        channel.send(message)

class ThingyTemplate:
    def __init__(self, test, engineID):
        self.engineID = engineID
        self.test = test
        self.passed = False

    def makeReply(self, message, pdu, securityLevel=None):
        if securityLevel is None:
            securityLevel = message.header.flags.securityLevel

        return SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(securityLevel),
                SecurityModel.USM,
            ),
            ScopedPDU(
                pdu.withRequestID(message.scopedPDU.pdu.requestID),
                self.engineID,
                message.scopedPDU.contextName,
            ),
            self.engineID,
            message.securityName,
        )

    def expectDiscovery(self, message):
        self.test.assertFalse(message.header.flags.authFlag)
        self.test.assertTrue(message.header.flags.reportableFlag)
        self.test.assertEqual(message.scopedPDU.contextEngineID, b"")
        self.test.assertEqual(message.securityEngineID, b"")
        self.test.assertEqual(message.securityName.userName, b"")

        pdu = message.scopedPDU.pdu
        self.test.assertNotEqual(pdu.requestID, 0)
        self.test.assertEqual(pdu.withRequestID(0), GetRequestPDU())

        oid = "1.3.6.1.6.3.15.1.1.4.0"
        value = Counter32(1)
        return self.makeReply(message, ReportPDU(VarBind(oid, value)))

    def hear(self, message, channel):
        raise NotImplemented()

class PacketCapture:
    def __init__(self):
        self.messages = []

    def hear(self, message, channel):
        self.messages.append(message)

class SNMPv3Manager3Tester(unittest.TestCase):
    class Sender:
        def send(self, message, channel):
            channel.send(message)

    def setUp(self):
        self.time = TimeFunction()
        self.sleep = SleepFunction(self.time)
        self.scheduler = Scheduler(self.sleep, self.time)

        self.sender = self.Sender()
        self.thingy = Thingy3()

        self.incoming = Channel(self.scheduler)
        self.outgoing = Channel(self.scheduler)

        self.userName = b"chuck"
        self.namespace = ""

        self.unknownEngineIDs = 0

    def connect(self, target):
        self.incoming.connect(self.thingy, self.outgoing)
        self.outgoing.connect(target, self.incoming)
        return target

    def interrupt(self, timeout):
        interrupt = InterruptTask()
        self.scheduler.schedule(interrupt, timeout)
        return interrupt

    def wait(self, interrupt):
        prev = self.time()
        while not interrupt.ready:
            self.scheduler.wait()
            now = self.time()

            if now == prev:
                raise RuntimeError("Interrupt is not scheduled")

            prev = now

    def expectDiscovery(self, message, engineID):
        self.assertFalse(message.header.flags.authFlag)
        self.assertTrue(message.header.flags.reportableFlag)
        self.assertEqual(message.scopedPDU.contextEngineID, b"")
        self.assertEqual(message.securityEngineID, b"")
        self.assertEqual(message.securityName.userName, b"")

        pdu = message.scopedPDU.pdu
        self.assertNotEqual(pdu.requestID, 0)
        self.assertEqual(pdu.withRequestID(0), GetRequestPDU())

        self.unknownEngineIDs += 1
        oid = "1.3.6.1.6.3.15.1.1.4.0"
        value = Counter32(self.unknownEngineIDs)
        report = ReportPDU(VarBind(oid, value))
        return self.makeReply(message, report, engineID)

    def makeManager(self, securityLevel=noAuthNoPriv, engineID=None):
        return SNMPv3Manager3(
            self.scheduler,
            self.thingy,
            self.sender,
            self.outgoing,
            self.namespace,
            self.userName,
            securityLevel,
            engineID,
        )

    def makeReply(self, message, pdu, engineID, securityLevel=None):
        if securityLevel is None:
            securityLevel = message.header.flags.securityLevel

        return SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(securityLevel),
                SecurityModel.USM,
            ),
            ScopedPDU(
                pdu.withRequestID(message.scopedPDU.pdu.requestID),
                engineID,
                message.scopedPDU.contextName,
            ),
            engineID,
            message.securityName,
        )

    def test_request_is_not_sent_if_discovery_is_needed(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        handle = manager.get("1.3.6.1.2.1.1.1.0")

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

    def test_request_securityLevel_does_not_apply_to_discovery(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        handle = manager.get("1.3.6.1.2.1.1.1.0")

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

    def test_only_send_discovery_request_once_for_multiple_requests(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0")
        h2 = manager.get("1.2.3.4.5.6")
        h3 = manager.get("1.3.6.1.2.1.2.2.1.2.1")

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

    def test_discovery_request_uses_refreshPeriod_of_the_first_request(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=3/8)
        h2 = manager.get("1.2.3.4.5.6", refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)

    def test_if_the_first_request_expires_discovery_uses_the_refreshPeriod_of_the_second_request(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=1/2, refreshPeriod=1.0)
        h2 = manager.get("1.2.3.4.5.6", timeout=1.625, refreshPeriod=3/8)
        h3 = manager.get("1.3.6.1.2.1.2.2.1.2.1", refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        # The discovery message outlives the first request
        self.wait(self.interrupt(1/2))
        self.assertEqual(len(pcap.messages), 0)

        # Wait for the first discovery message to expire
        self.wait(self.interrupt(7/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        # The new discovery message has the refreshPeriod of the second request
        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        # The second request has expired by now
        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        # The new discovery message has the refreshPeriod of the third request
        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

    def test_if_all_requests_expire_stop_sending_discovery_messages(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=1/2, refreshPeriod=1.0)
        h2 = manager.get("1.2.3.4.5.6", timeout=1.75, refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        # The second request has expired by now
        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 0)

    def test_restart_discovery_messages_when_a_new_request_is_made(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()

        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=1/2, refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(3.0))
        self.assertEqual(len(pcap.messages), 0)

        h2 = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

    def test_discovery_resets_when_restarted_before_old_disc_msg_expires(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=1/2, refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(3/4))
        self.assertEqual(len(pcap.messages), 0)

        h2 = manager.get("1.2.3.4.5.6", timeout=3.0, refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        # Check that the message from the first request does not refresh
        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(1/2))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        # Check that the message from the first request still does not refresh
        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

    def test_send_request_message_as_soon_as_discovery_is_complete(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=5.0, refreshPeriod=1.0)

        interrupt = self.interrupt(1/32)
        self.assertEqual(len(pcap.messages), 1)
        discoveryReply = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(interrupt)
        self.assertEqual(len(pcap.messages), 0)

        self.incoming.send(discoveryReply)
        self.assertEqual(len(pcap.messages), 1)

        message = pcap.messages.pop()
        self.assertFalse(message.header.flags.authFlag)
        self.assertEqual(message.securityEngineID, b"remote")
        self.assertEqual(message.securityName.userName, self.userName)

        scopedPDU = message.scopedPDU
        self.assertEqual(scopedPDU.contextEngineID, b"remote")
        #self.assertEqual(scopedPDU.contextName, b"???")

        pdu = scopedPDU.pdu
        self.assertNotEqual(pdu.requestID, 0)
        self.assertEqual(pdu.errorStatus, ErrorStatus.noError)
        self.assertEqual(len(pdu.variableBindings), 1)

        vb = pdu.variableBindings[0]
        self.assertEqual(vb.name, OID(1,3,6,1,2,1,1,1,0))
        self.assertEqual(vb.value, Null())

    def test_send_all_requests_as_soon_as_discovery_is_complete(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=5.0, refreshPeriod=1.0)
        h2 = manager.get("1.2.3.4.5.6")
        h3 = manager.get("1.3.6.1.2.1.2.2.1.2.1")

        interrupt = self.interrupt(1/32)
        self.assertEqual(len(pcap.messages), 1)
        discoveryReply = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(interrupt)
        self.assertEqual(len(pcap.messages), 0)

        self.incoming.send(discoveryReply)
        self.assertEqual(len(pcap.messages), 3)

        oids = {
            OID.parse("1.3.6.1.2.1.1.1.0"),
            OID.parse("1.2.3.4.5.6"),
            OID.parse("1.3.6.1.2.1.2.2.1.2.1"),
        }

        while pcap.messages:
            message = pcap.messages.pop()
            self.assertFalse(message.header.flags.authFlag)
            self.assertEqual(message.securityEngineID, b"remote")
            self.assertEqual(message.securityName.userName, self.userName)

            scopedPDU = message.scopedPDU
            self.assertEqual(scopedPDU.contextEngineID, b"remote")
            #self.assertEqual(scopedPDU.contextName, b"???")

            pdu = scopedPDU.pdu
            self.assertNotEqual(pdu.requestID, 0)
            self.assertEqual(pdu.errorStatus, ErrorStatus.noError)
            self.assertEqual(len(pdu.variableBindings), 1)

            vb = pdu.variableBindings[0]
            self.assertIn(vb.name, oids)
            self.assertEqual(vb.value, Null())
            oids.remove(vb.name)

        self.assertEqual(len(oids), 0)

    def test_do_not_send_requests_that_expired_during_discovery(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=1.5, refreshPeriod=1.0)
        h2 = manager.get("1.2.3.4.5.6", timeout=3.0, refreshPeriod=1.0)
        h3 = manager.get("1.3.6.1.2.1.2.2.1.2.1", timeout=3.0)

        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(1.0))
        self.assertEqual(len(pcap.messages), 1)
        discoveryReply = self.expectDiscovery(pcap.messages.pop(), b"remote")

        # The first request has expired by now
        self.wait(self.interrupt(3/4))
        self.assertEqual(len(pcap.messages), 0)

        self.incoming.send(discoveryReply)
        self.assertEqual(len(pcap.messages), 2)

        oids = {
            OID.parse("1.2.3.4.5.6"),
            OID.parse("1.3.6.1.2.1.2.2.1.2.1"),
        }

        while pcap.messages:
            message = pcap.messages.pop()
            self.assertFalse(message.header.flags.authFlag)
            self.assertEqual(message.securityEngineID, b"remote")
            self.assertEqual(message.securityName.userName, self.userName)

            scopedPDU = message.scopedPDU
            self.assertEqual(scopedPDU.contextEngineID, b"remote")
            #self.assertEqual(scopedPDU.contextName, b"???")

            pdu = scopedPDU.pdu
            self.assertNotEqual(pdu.requestID, 0)
            self.assertEqual(pdu.errorStatus, ErrorStatus.noError)
            self.assertEqual(len(pdu.variableBindings), 1)

            vb = pdu.variableBindings[0]
            self.assertIn(vb.name, oids)
            self.assertEqual(vb.value, Null())
            oids.remove(vb.name)

        self.assertEqual(len(oids), 0)

    def test_request_messages_refresh_every_refreshPeriod(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=5.0, refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, h1.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,3,6,1,2,1,1,1,0))

        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, h1.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,3,6,1,2,1,1,1,0))

        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, h1.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,3,6,1,2,1,1,1,0))

    def test_every_refresh_has_a_new_messageID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=5.0, refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        messageID = message.header.msgID

        self.wait(self.interrupt(1.0))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        self.assertNotEqual(message.header.msgID, messageID)
        messageID = message.header.msgID

        self.wait(self.interrupt(1.0))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        self.assertNotEqual(message.header.msgID, messageID)
        messageID = message.header.msgID

    def test_each_request_refreshes_at_its_own_rate(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=5.0, refreshPeriod=7/16)
        h2 = manager.get("1.2.3.4.5.6", timeout=3.0, refreshPeriod=3/4)
        h3 = manager.get("1.3.6.1.2.1.2.2.1.2.1", refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 3)
        pcap.messages.clear()

        self.wait(self.interrupt(6/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, h1.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,3,6,1,2,1,1,1,0))

        self.wait(self.interrupt(4/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, h2.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,2,3,4,5,6))

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, h1.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,3,6,1,2,1,1,1,0))

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, h3.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,3,6,1,2,1,2,2,1,2,1))

    def test_handle_raises_Timeout_after_timeout_if_there_is_no_response(self):
        manager = self.makeManager(engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", timeout=3.375)
        self.assertRaises(Timeout, handle.wait)
        self.assertEqual(self.time(), 3.375)

    def test_no_discovery_message_sent_if_timeout_is_zero(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        handle = manager.get("1.3.6.1.2.1.1.1.0", timeout=0.0)
        self.assertEqual(len(pcap.messages), 0)

    def test_no_messages_sent_during_discovery_if_timeout_is_zero(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0")
        self.assertEqual(len(pcap.messages), 1)
        _ = self.expectDiscovery(pcap.messages.pop(), b"remote")
        h2 = manager.get("1.3.6.1.2.1.1.1.0", timeout=0.0)
        self.assertEqual(len(pcap.messages), 0)

    def test_no_messages_sent_during_normal_operation_if_timeout_is_zero(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        h1 = manager.get("1.3.6.1.2.1.1.1.0")
        self.assertEqual(len(pcap.messages), 1)
        pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", timeout=0.0)
        self.assertEqual(len(pcap.messages), 0)

    def test_request_timeout_includes_time_spent_on_discovery(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        handle = manager.get("1.3.6.1.2.1.1.1.0", timeout=1/2)

        self.assertEqual(len(pcap.messages), 1)
        discoveryReply = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(1/4))
        self.incoming.send(discoveryReply)

        self.assertRaises(Timeout, handle.wait)
        self.assertEqual(self.time(), 1/2)

    def test_request_refresh_clock_starts_when_request_is_sent(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        handle = manager.get("1.2.3.4.5.6", timeout=3.0, refreshPeriod=1/2)

        self.assertEqual(len(pcap.messages), 1)
        discoveryReply = self.expectDiscovery(pcap.messages.pop(), b"remote")

        self.wait(self.interrupt(1/4))
        self.incoming.send(discoveryReply)

        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, handle.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,2,3,4,5,6))

        self.wait(self.interrupt(7/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        pdu = message.scopedPDU.pdu
        self.assertEqual(pdu.requestID, handle.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,2,3,4,5,6))

    def test_handle_returns_VarBindList_upon_receiving_a_vaild_response(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.incoming.send(SNMPv3Message(
            HeaderData(
                message.header.msgID,
                1472,
                MessageFlags(message.header.flags.securityLevel),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ResponsePDU(
                    VarBind("1.2.3.4.5.6", Integer(123456)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        ))

        vblist = handle.wait()
        self.assertEqual(len(vblist), 1)

        vb = vblist[0]
        self.assertEqual(vb.name, OID(1,2,3,4,5,6))
        self.assertEqual(vb.value, Integer(123456))

    def test_raise_UnsupportedSecLevel_on_next_refresh_if_reported(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsUnsupportedSecLevelsInstance,
                        Counter32(1),
                    ),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        self.assertRaises(UnsupportedSecLevel, handle.wait)
        self.assertEqual(self.time(), 17/16)

    def test_raise_UnsupportedSecLevel_immediately_if_reported_with_auth(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1.0)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(authNoPriv),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsUnsupportedSecLevelsInstance,
                        Counter32(1),
                    ),
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(UnsupportedSecLevel, handle.wait)
        self.assertEqual(self.time(), 1/4)

    def test_resend_auth_message_after_notInTimeWindow_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(usmStatsNotInTimeWindowsInstance, Counter32(1)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        self.assertEqual(len(pcap.messages), 1)

        message = pcap.messages.pop()
        self.assertEqual(message.securityEngineID, b"remote")
        self.assertEqual(message.securityName.userName, self.userName)
        self.assertEqual(len(message.securityName.namespaces), 1)
        self.assertIn(self.namespace, message.securityName.namespaces)

        self.assertTrue(message.header.flags.authFlag)
        self.assertFalse(message.header.flags.privFlag)
        self.assertTrue(message.header.flags.reportableFlag)

        scopedPDU = message.scopedPDU
        self.assertEqual(scopedPDU.contextEngineID, b"remote")
        #self.assertEqual(scopedPDU.contextName, b"???")

        pdu = scopedPDU.pdu
        self.assertEqual(pdu.requestID, handle.requestID)
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,2,3,4,5,6))

    def test_notInTimeWindow_report_resets_refresh(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1.0)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(usmStatsNotInTimeWindowsInstance, Counter32(1)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertEqual(len(pcap.messages), 1)
        pcap.messages.pop()

        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)

    def test_raise_UnknownUserName_immediately_if_auth_not_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", userName=b"invalidUserName")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsUnknownUserNamesInstance,
                        Counter32(1),
                    ),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(b"invalidUserName"),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(UnknownUserName, handle.wait)
        self.assertEqual(self.time(), 1/4)

    def test_raise_UnknownUserName_on_next_refresh_if_auth_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get(
            "1.2.3.4.5.6",
            userName=b"invalidUserName",
            refreshPeriod=17/16,
        )
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsUnknownUserNamesInstance,
                        Counter32(1),
                    ),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(b"invalidUserName"),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(UnknownUserName, handle.wait)
        self.assertEqual(self.time(), 17/16)

    def test_raise_WrongDigest_on_next_refresh_if_auth_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsWrongDigestsInstance,
                        Counter32(1),
                    ),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(WrongDigest, handle.wait)
        self.assertEqual(self.time(), 17/16)

    def test_ignore_WrongDigest_report_if_auth_not_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", timeout=3.5)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsWrongDigestsInstance,
                        Counter32(1),
                    ),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(Timeout, handle.wait)
        self.assertEqual(self.time(), 3.5)

    def test_raise_DecryptionError_on_next_refresh_if_report_has_no_auth(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsDecryptionErrorsInstance,
                        Counter32(1),
                    ),
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(DecryptionError, handle.wait)
        self.assertEqual(self.time(), 17/16)

    def test_raise_DecryptionError_immediately_if_report_has_auth(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(authNoPriv),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsDecryptionErrorsInstance,
                        Counter32(1),
                    ),
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(DecryptionError, handle.wait)
        self.assertEqual(self.time(), 1/4)

    def test_ignore_DecryptionError_if_priv_not_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", timeout=3.5)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(
                        usmStatsDecryptionErrorsInstance,
                        Counter32(1),
                    ),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.wait(self.interrupt(1/4))
        self.incoming.send(message)
        self.assertRaises(Timeout, handle.wait)
        self.assertEqual(self.time(), 3.5)

    def test_resend_noAuth_message_with_new_engine_after_UnknownEngineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remove")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(usmStatsUnknownEngineIDsInstance, Counter32(1)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        self.assertEqual(len(pcap.messages), 1)
        newMessage = pcap.messages.pop()

        vblist = newMessage.scopedPDU.pdu.variableBindings
        self.assertEqual(len(vblist), 1)
        self.assertEqual(vblist[0].name, OID(1,2,3,4,5,6))
        self.assertEqual(vblist[0].value, Null())

        self.assertEqual(newMessage.scopedPDU.contextEngineID, b"remote")
        self.assertEqual(newMessage.securityEngineID, b"remote")

        self.assertEqual(newMessage.securityName.userName, self.userName)
        self.assertEqual(len(newMessage.securityName.namespaces), 1)
        self.assertIn(self.namespace, newMessage.securityName.namespaces)

    def test_UnknownEngineID_report_overwrites_unauthenticated_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remove")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(usmStatsUnknownEngineIDsInstance, Counter32(1)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        self.assertEqual(len(pcap.messages), 1)
        pcap.messages.pop()

        # Send a new request; this one should have the updated engine ID
        manager.get("1.3.6.1.2.1.1.1.0")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        vblist = message.scopedPDU.pdu.variableBindings
        self.assertEqual(len(vblist), 1)
        self.assertEqual(vblist[0].name, OID(1,3,6,1,2,1,1,1,0))

        self.assertEqual(message.scopedPDU.contextEngineID, b"remote")
        self.assertEqual(message.securityEngineID, b"remote")

    def test_UnknownEngineID_after_auth_has_no_effect_on_noAuth_request(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        handle = manager.get("1.2.3.4.5.6")

        self.assertEqual(len(pcap.messages), 1)
        discovery = self.expectDiscovery(pcap.messages.pop(), b"remote")
        self.incoming.send(discovery)

        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(authNoPriv),
                message.header.securityModel,
            ),
            ScopedPDU(
                ResponsePDU(
                    VarBind("1.2.3.4.5.6", Integer(123456)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        _ = handle.wait()

        handle = manager.get("1.2.3.4.5.6", securityLevel=noAuthNoPriv)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(noAuthNoPriv),
                message.header.securityModel,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(usmStatsUnknownEngineIDsInstance, Counter32(1)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"different",
            ),
            b"different",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        self.assertEqual(len(pcap.messages), 0)
        # TODO: Maybe raise UnknownEngineID error on next refresh

    def test_auth_response_confirms_preconfigured_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(authNoPriv),
                message.header.securityModel,
            ),
            ScopedPDU(
                ResponsePDU(
                    VarBind("1.2.3.4.5.6", Integer(123456)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"remote",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        _ = handle.wait()

        handle = manager.get("1.2.3.4.5.6", securityLevel=noAuthNoPriv)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        message = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(noAuthNoPriv),
                message.header.securityModel,
            ),
            ScopedPDU(
                ReportPDU(
                    VarBind(usmStatsUnknownEngineIDsInstance, Counter32(1)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                b"different",
            ),
            b"different",
            SecurityName(self.userName, self.namespace),
        )

        self.incoming.send(message)
        self.assertEqual(len(pcap.messages), 0)

# noAuthNoPriv, engineID not authenticated
# - overwrite engineID
# authNoPriv, engineID not authenticated
# - re-send only that message
# authPriv, engineID not authenticated
# - re-send only that message
# noAuthNoPriv, engineID authenticated
# - certainly don't overwrite engineID
# - raise Exception on next refresh?
# authNoPriv, engineID authenticated
# - re-send only that message
# authPriv, engineID authenticated
# - re-send only that message
# When engineID is updated, re-send all outstanding requests

# TODO: Test all the possible cases when a discovery message could be used
# - ???
# - ???
# TODO: Test with different security levels
# TODO: Test with fraudulent messages (make sure it keeps sending with the original engineID)
# TODO: Test overwriting the manager's engineID
# TODO: Test cooldown period

# TODO: If you delete a manager, make sure it releases all message IDs
# TODO: Test a valid messageID that is matched with the wrong request
# TODO: contextName
# TODO: Only handle NotInTimeWindow once, then raise the exception
# TODO: Test that messages are cancelled as needed
#       - this applies to UnknownEngineID and NotInTimeWindow, but also when self.engineID is updated

if __name__ == "__main__":
    unittest.main(verbosity=2)
