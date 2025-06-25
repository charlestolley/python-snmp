__all__ = ["SNMPv3Manager3Test"]
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
    def __init__(self):
        self.partner = None
        self.target = None

    def connect(self, target, channel):
        self.partner = channel
        self.target = target

    def send(self, message):
        if self.target is not None:
            self.target.hear(message, self.partner)

class PacketCapture:
    def __init__(self):
        self.messages = []

    def hear(self, message, channel):
        self.messages.append(message)

class RespondTask(SchedulerTask):
    def __init__(self, test, pcap, varbind):
        self.pcap = pcap
        self.test = test
        self.varbind = varbind

    def run(self):
        message = self.pcap.messages.pop()
        self.test.respond(message, self.varbind)

class SNMPv3Manager3Test(unittest.TestCase):
    class Sender:
        def send(self, message, channel):
            channel.send(message)

    def setUp(self):
        self.time = TimeFunction()
        self.sleep = SleepFunction(self.time)
        self.scheduler = Scheduler(self.sleep, self.time)

        self.sender = self.Sender()
        self.router = SNMPv3MessageRouter()

        self.incoming = Channel()
        self.outgoing = Channel()

        self.userName = b"chuck"
        self.namespace = ""

        self.unsupportedSecLevels = 0
        self.notInTimeWindows = 0
        self.unknownUserNames = 0
        self.unknownEngineIDs = 0
        self.wrongDigests = 0
        self.decryptionErrors = 0

    def tearDown(self):
        prev = self.time()
        self.scheduler.wait()
        now = self.time()

        while now != prev:
            prev = now
            self.scheduler.wait()
            now = self.time()

        self.assertEqual(len(self.router.authority.reserved), 0)

    def connect(self, target):
        self.incoming.connect(self.router, self.outgoing)
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

    def makeManager(self, securityLevel=noAuthNoPriv, engineID=None, autowait=False):
        return SNMPv3Manager(
            self.scheduler,
            self.router,
            self.sender,
            self.outgoing,
            self.namespace,
            self.userName,
            securityLevel,
            engineID,
            autowait,
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

    def report(self, message, varbind, securityLevel):
        reply = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(securityLevel),
                message.header.securityModel,
            ),
            ScopedPDU(
                ReportPDU(varbind, requestID=message.scopedPDU.pdu.requestID),
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            message.securityName,
        )

        self.incoming.send(reply)

    def respond(self, message, *varbinds, securityLevel=None, **kwargs):
        if securityLevel is None:
            securityLevel = message.header.flags.securityLevel

        kwargs.setdefault("requestID", message.scopedPDU.pdu.requestID)

        reply = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(securityLevel),
                message.header.securityModel,
            ),
            ScopedPDU(
                ResponsePDU(*varbinds, **kwargs),
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            message.securityName,
        )

        self.incoming.send(reply)

    def expectDiscovery(self, message):
        self.assertFalse(message.header.flags.authFlag)
        self.assertTrue(message.header.flags.reportableFlag)
        self.assertEqual(message.scopedPDU.contextEngineID, b"")
        self.assertEqual(message.securityEngineID, b"")
        self.assertEqual(message.securityName.userName, b"")

        pdu = message.scopedPDU.pdu
        self.assertNotEqual(pdu.requestID, 0)
        self.assertEqual(pdu.withRequestID(0), GetRequestPDU())

        return message

    def reportUnsupportedSecLevel(self, message, securityLevel):
        self.unsupportedSecLevels += 1
        oid = usmStatsUnsupportedSecLevelsInstance
        value = Counter32(self.unsupportedSecLevels)
        varbind = VarBind(oid, value)
        self.report(message, varbind, securityLevel)

    def reportNotInTimeWindows(self, message, auth):
        self.notInTimeWindows += 1
        oid = usmStatsNotInTimeWindowsInstance
        value = Counter32(self.notInTimeWindows)
        varbind = VarBind(oid, value)
        self.report(message, varbind, SecurityLevel(auth))

    def reportUnknownUserName(self, message, auth=False):
        self.unknownUserNames += 1
        oid = usmStatsUnknownUserNamesInstance
        value = Counter32(self.unknownUserNames)
        varbind = VarBind(oid, value)
        self.report(message, varbind, SecurityLevel(auth))

    def reportUnknownEngineID(self, message, engineID):
        self.unknownEngineIDs += 1
        oid = usmStatsUnknownEngineIDsInstance
        value = Counter32(self.unknownEngineIDs)
        varbind = VarBind(oid, value)

        reply = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                message.header.securityModel,
            ),
            ScopedPDU(
                ReportPDU(varbind, requestID=message.scopedPDU.pdu.requestID),
                engineID,
                message.scopedPDU.contextName,
            ),
            engineID,
            message.securityName,
        )

        self.incoming.send(reply)

    def reportWrongDigest(self, message, auth=False):
        self.wrongDigests += 1
        oid = usmStatsWrongDigestsInstance
        value = Counter32(self.wrongDigests)
        varbind = VarBind(oid, value)
        self.report(message, varbind, SecurityLevel(auth))

    def reportDecryptionError(self, message, auth=False):
        self.decryptionErrors += 1
        oid = usmStatsDecryptionErrorsInstance
        value = Counter32(self.decryptionErrors)
        varbind = VarBind(oid, value)
        self.report(message, varbind, SecurityLevel(auth))

    def discover(self, manager, pcap, engineID, auth=False):
        handle = manager.get("1.2.3.4.5.6", securityLevel=SecurityLevel(auth))
        message = self.expectDiscovery(pcap.messages.pop())
        self.reportUnknownEngineID(message, engineID)

        message = pcap.messages.pop()
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind, securityLevel=SecurityLevel(auth))

        vblist = handle.wait()
        self.assertEqual(len(vblist), 1)
        self.assertEqual(vblist[0].name, OID(1,2,3,4,5,6))
        self.assertEqual(vblist[0].value, Integer(123456))

    def test_request_is_not_sent_if_discovery_is_needed(self):
        pcap = self.connect(PacketCapture())
        self.manager = self.makeManager()
        handle = self.manager.get("1.3.6.1.2.1.1.1.0")

        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

    def test_request_securityLevel_does_not_apply_to_discovery(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        handle = manager.get("1.3.6.1.2.1.1.1.0")

        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

    def test_only_send_discovery_request_once_for_multiple_requests(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0")
        h2 = manager.get("1.2.3.4.5.6")
        h3 = manager.get("1.3.6.1.2.1.2.2.1.2.1")

        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

    def test_discovery_request_uses_refreshPeriod_of_the_first_request(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=3/8)
        h2 = manager.get("1.2.3.4.5.6", refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

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
        self.expectDiscovery(pcap.messages.pop())

        # The discovery message outlives the first request
        self.wait(self.interrupt(1/2))
        self.assertEqual(len(pcap.messages), 0)

        # Wait for the first discovery message to expire
        self.wait(self.interrupt(7/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        # The new discovery message has the refreshPeriod of the second request
        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(5/16))
        self.assertEqual(len(pcap.messages), 0)

        # The second request has expired by now
        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        # The new discovery message has the refreshPeriod of the third request
        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

    def test_if_all_requests_expire_stop_sending_discovery_messages(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=1/2, refreshPeriod=1.0)
        h2 = manager.get("1.2.3.4.5.6", timeout=1.75, refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

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
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(3.0))
        self.assertEqual(len(pcap.messages), 0)

        h2 = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

    def test_discovery_resets_when_restarted_before_old_disc_msg_expires(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=1/2, refreshPeriod=1.0)

        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(3/4))
        self.assertEqual(len(pcap.messages), 0)

        h2 = manager.get("1.2.3.4.5.6", timeout=3.0, refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        # Check that the message from the first request does not refresh
        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(1/2))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

        # Check that the message from the first request still does not refresh
        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 1)
        self.expectDiscovery(pcap.messages.pop())

    def test_send_request_message_as_soon_as_discovery_is_complete(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        h1 = manager.get("1.3.6.1.2.1.1.1.0", timeout=5.0, refreshPeriod=1.0)

        interrupt = self.interrupt(1/32)
        self.assertEqual(len(pcap.messages), 1)
        message = self.expectDiscovery(pcap.messages.pop())

        self.wait(interrupt)
        self.assertEqual(len(pcap.messages), 0)

        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)

        message = pcap.messages.pop()
        self.assertFalse(message.header.flags.authFlag)
        self.assertEqual(message.securityEngineID, b"remote")
        self.assertEqual(message.securityName.userName, self.userName)

        scopedPDU = message.scopedPDU
        self.assertEqual(scopedPDU.contextEngineID, b"remote")
        self.assertEqual(scopedPDU.contextName, b"")

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
        message = self.expectDiscovery(pcap.messages.pop())

        self.wait(interrupt)
        self.assertEqual(len(pcap.messages), 0)

        self.reportUnknownEngineID(message, b"remote")
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
            self.assertEqual(scopedPDU.contextName, b"")

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
        self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(1.0))
        self.assertEqual(len(pcap.messages), 1)
        message = self.expectDiscovery(pcap.messages.pop())

        # The first request has expired by now
        self.wait(self.interrupt(3/4))
        self.assertEqual(len(pcap.messages), 0)

        self.reportUnknownEngineID(message, b"remote")
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
            self.assertEqual(scopedPDU.contextName, b"")

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
        self.expectDiscovery(pcap.messages.pop())
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
        message = self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")

        self.assertRaises(Timeout, handle.wait)
        self.assertEqual(self.time(), 1/2)

    def test_request_refresh_clock_starts_when_request_is_sent(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        handle = manager.get("1.2.3.4.5.6", timeout=3.0, refreshPeriod=1/2)

        self.assertEqual(len(pcap.messages), 1)
        message = self.expectDiscovery(pcap.messages.pop())

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")

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

        self.respond(message, VarBind("1.2.3.4.5.6", Integer(123456)))

        vblist = handle.wait()
        self.assertEqual(len(vblist), 1)

        vb = vblist[0]
        self.assertEqual(vb.name, OID(1,2,3,4,5,6))
        self.assertEqual(vb.value, Integer(123456))

    def test_noAuth_request_unconfirmed_engineID_UnknownEngineID_resends_with_the_new_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_noAuth_request_unconfirmed_engineID_UnknownEngineID_does_not_cancel_original_message(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(3/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"different")

    def test_noAuth_request_unconfirmed_engineID_UnknownEngineID_containing_the_original_engineID_is_ignored(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"different")

        self.assertEqual(len(pcap.messages), 0)

    def test_noAuth_request_unconfirmed_engineID_a_new_request_sent_after_receiving_an_UnknownEngineID_still_uses_the_old_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"different")

    def test_noAuth_request_unconfirmed_engineID_a_new_request_sent_after_receiving_an_UnknownEngineID_resends_after_the_first_message_receives_a_response(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        m1 = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.respond(m1, VarBind("1.2.3.4.5.6", Integer(123456)))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.scopedPDU.pdu.requestID, h2.requestID)
        self.assertEqual(message.securityEngineID, b"remote")

    def test_noAuth_request_unconfirmed_engineID_a_new_request_sent_after_receiving_an_UnknownEngineID_no_longer_refreshes_with_the_old_engineID_after_the_response_to_the_first_request(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(3/8))
        self.assertEqual(len(pcap.messages), 0)

    def test_noAuth_request_unconfirmed_engineID_a_new_request_sent_after_receiving_an_UnknownEngineID_no_longer_refreshes_with_the_engineID_it_got_from_an_UnknownEngineID_report_after_the_response_to_the_first_request(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        m1 = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        m2 = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(m2, b"unheardOf")
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(m1, varbind)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/8))
        self.assertEqual(len(pcap.messages), 0)

    def test_noAuth_request_unconfirmed_engineID_a_new_request_sent_after_receiving_an_UnknownEngineID_still_refreshes_with_the_new_engineID_which_it_got_from_an_UnknownEngineID_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        m1 = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        m2 = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(m2, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(m1, varbind)
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(3/8))
        self.assertEqual(len(pcap.messages), 1)

    def test_noAuth_request_unconfirmed_engineID_a_new_request_sent_after_receiving_an_UnknownEngineID_that_sent_with_a_new_engineID_will_not_resend_with_the_old_one(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"different")
        self.assertEqual(len(pcap.messages), 0)

    def test_noAuth_request_after_unconfirmed_rediscovery_uses_the_new_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        vblist = handle.wait()

        handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_auth_request_unconfirmed_engineID_UnknownEngineID_resends_with_the_new_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_auth_request_unconfirmed_engineID_UnknownEngineID_does_not_cancel_the_original_message(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(3/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"different")

    def test_auth_request_unconfirmed_engineID_a_second_UnknownEngineID_with_the_original_engineID_does_nothing(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"different")

        self.assertEqual(len(pcap.messages), 0)

    def test_auth_request_unconfirmed_engineID_a_new_request_after_UnknownEngineID_uses_the_old_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"different")

    def test_auth_request_unconfirmed_engineID_a_new_request_after_UnknownEngineID_resends_with_the_new_engineID_after_response(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different")

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.scopedPDU.pdu.requestID, h2.requestID)
        self.assertEqual(message.securityEngineID, b"remote")

    def test_auth_request_unconfirmed_engineID_a_new_request_after_auth_response_uses_the_new_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        vblist = handle.wait()

        handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_noAuth_request_confirmed_engineID_UnknownEngineID_resends_with_the_new_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"remote", True)

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnknownEngineID(message, b"different")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"different")

    def test_noAuth_request_confirmed_engineID_still_refreshes_with_old_engineID_after_UnknownEngineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"remote", True)

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=3/4)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"different")
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(1/2))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        self.assertEqual(message.securityEngineID, b"remote")

    def test_noAuth_request_confirmed_engineID_a_new_request_sent_after_receiving_an_UnknownEngineID_still_uses_the_old_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"remote", True)

        h1 = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnknownEngineID(message, b"different")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", securityLevel=noAuthNoPriv)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_noAuth_request_confirmed_engineID_other_requests_are_not_affected_when_a_response_with_a_different_engineID_is_accepted(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"remote", True)

        h1 = manager.get("1.2.3.4.5.6", securityLevel=noAuthNoPriv)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnknownEngineID(message, b"different")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", securityLevel=noAuthNoPriv)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        self.assertEqual(len(pcap.messages), 0)

    def test_noAuth_request_confirmed_engineID_requests_sent_after_a_response_with_a_different_engineID_is_accepted_use_the_old_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager()
        self.discover(manager, pcap, b"remote", True)

        h1 = manager.get("1.2.3.4.5.6")

        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        self.reportUnknownEngineID(message, b"different")

        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        _ = h1.wait()

        manager.get("1.3.6.1.2.1.1.1.0")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_auth_request_confirmed_engineID_UnknownEngineID_resends_with_the_new_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different", True)

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_auth_request_confirmed_engineID_UnknownEngineID_does_not_cancel_the_original_message(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different", True)

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(3/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"different")

    def test_auth_request_confirmed_engineID_a_second_UnknownEngineID_with_the_original_engineID_does_nothing(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different", True)

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"different")

        self.assertEqual(len(pcap.messages), 0)

    def test_auth_request_confirmed_engineID_a_new_request_after_UnknownEngineID_uses_the_old_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different", True)

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"different")

    def test_auth_request_confirmed_engineID_a_new_request_after_UnknownEngineID_resends_with_the_new_engineID_after_response(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different", True)

        h1 = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        h2 = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.scopedPDU.pdu.requestID, h2.requestID)
        self.assertEqual(message.securityEngineID, b"remote")

    def test_auth_request_confirmed_engineID_a_new_request_after_auth_response_uses_the_new_engineID(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv)
        self.discover(manager, pcap, b"different", True)

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/8))
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)
        vblist = handle.wait()

        handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1/2)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.securityEngineID, b"remote")

    def test_UnknownEngineID_with_the_same_engineID_is_ignored(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnknownEngineID(message, b"remote")
        self.assertEqual(len(pcap.messages), 0)

    def test_noAuth_request_ignores_NotInTimeWindows_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportNotInTimeWindows(message, False)
        self.assertEqual(len(pcap.messages), 0)

    def test_resend_auth_message_after_notInTimeWindow_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportNotInTimeWindows(message, False)
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
        self.assertEqual(scopedPDU.contextName, b"")

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

        self.wait(self.interrupt(1/4))
        self.reportNotInTimeWindows(message, False)
        self.assertEqual(len(pcap.messages), 1)
        _ = pcap.messages.pop()

        self.wait(self.interrupt(15/16))
        self.assertEqual(len(pcap.messages), 0)

        self.wait(self.interrupt(1/16))
        self.assertEqual(len(pcap.messages), 1)

    def test_second_NotInTimeWindows_report_with_auth_raises_exception_immediately(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportNotInTimeWindows(message, True)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportNotInTimeWindows(message, True)
        self.assertEqual(len(pcap.messages), 0)
        self.assertRaises(TimeWindowFailure, handle.wait)
        self.assertEqual(self.time(), 1/2)

    def test_second_NotInTimeWindows_report_without_auth_raises_exception_on_next_refresh(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1.0)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportNotInTimeWindows(message, False)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportNotInTimeWindows(message, False)
        self.assertEqual(len(pcap.messages), 0)
        self.assertRaises(TimeWindowFailure, handle.wait)
        self.assertEqual(self.time(), 5/4)

    def test_noAuth_request_ignore_UnsupportedSecLevel_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnsupportedSecLevel(message, noAuthNoPriv)
        self.assertRaises(Timeout, handle.wait)

    def test_auth_request_noAuth_report_raise_UnsupportedSecurityLevel_on_next_refresh(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnsupportedSecLevel(message, noAuthNoPriv)
        self.assertRaises(UnsupportedSecurityLevel, handle.wait)
        self.assertEqual(self.time(), 17/16)

    def test_auth_request_auth_report_ignore_UnsupportedSecLevel_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnsupportedSecLevel(message, authNoPriv)
        self.assertRaises(Timeout, handle.wait)

    def test_authPriv_request_auth_report_raise_UnsupportedSecurityLevel_immediately(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1.0)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnsupportedSecLevel(message, authNoPriv)
        self.assertRaises(UnsupportedSecurityLevel, handle.wait)
        self.assertEqual(self.time(), 1/4)

    def test_authPriv_request_authPriv_report_raise_UnsupportedSecLevel_immediately(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=1.0)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.reportUnsupportedSecLevel(message, authPriv)
        self.assertRaises(Timeout, handle.wait)

    def test_noAuth_request_raise_UnknownUserName_on_next_refresh(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", userName=b"???", refreshPeriod=9/8)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownUserName(message)
        self.assertRaises(UnknownUserName, handle.wait)
        self.assertEqual(self.time(), 9/8)

    def test_auth_request_raise_UnknownUserName_on_nextRefresh(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", userName=b"???", refreshPeriod=9/8)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownUserName(message)
        self.assertRaises(UnknownUserName, handle.wait)
        self.assertEqual(self.time(), 9/8)

    def test_auth_request_auth_report_ignore_UnknownUserName(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportUnknownUserName(message, True)
        self.assertRaises(Timeout, handle.wait)

    def test_raise_WrongDigest_on_next_refresh_if_auth_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportWrongDigest(message)
        self.assertRaises(AuthenticationFailure, handle.wait)
        self.assertEqual(self.time(), 17/16)

    def test_ignore_WrongDigest_report_if_auth_not_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6", timeout=3.5)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportWrongDigest(message)

        self.assertRaises(Timeout, handle.wait)
        self.assertEqual(self.time(), 3.5)

    def test_raise_DecryptionError_on_next_refresh_if_report_has_no_auth(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportDecryptionError(message, False)
        self.assertRaises(PrivacyFailure, handle.wait)
        self.assertEqual(self.time(), 17/16)

    def test_raise_DecryptionError_immediately_if_report_has_auth(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=17/16)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportDecryptionError(message, True)
        self.assertRaises(PrivacyFailure, handle.wait)
        self.assertEqual(self.time(), 1/4)

    def test_ignore_DecryptionError_if_priv_not_requested(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", timeout=3.5)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        self.reportDecryptionError(message, False)

        self.assertRaises(Timeout, handle.wait)
        self.assertEqual(self.time(), 3.5)

    def test_raise_UnhandledReport_on_next_refresh_after_noAuth_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=3/4)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        varbind = VarBind(OID.parse("1.3.5.7.9"), Integer(24))
        self.report(message, varbind, noAuthNoPriv)

        try:
            handle.wait()
        except UnhandledReport as err:
            self.assertEqual(err.report, varbind)
        else:
            self.assertTrue(False)

        self.assertEqual(self.time(), 3/4)

    def test_raise_UnhandledReport_immediately_after_auth_report(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", refreshPeriod=3/4)
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.wait(self.interrupt(1/4))
        varbind = VarBind(OID.parse("1.3.5.7.9"), Integer(24))
        self.report(message, varbind, authNoPriv)

        try:
            handle.wait()
        except UnhandledReport as err:
            self.assertEqual(err.report, varbind)
        else:
            self.assertTrue(False)

        self.assertEqual(self.time(), 1/4)

    def test_IncomingMessageError_if_requestID_does_not_match(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        requestID = 1757
        if requestID == message.scopedPDU.pdu.requestID:
            requestID += 1

        self.assertRaises(
            IncomingMessageError,
            self.respond,
            message,
            VarBind("1.2.3.4.5.6", Integer(123456)),
            requestID=requestID,
        )

    def test_IncomingMessageError_if_response_securityLevel_is_too_low(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        oid = OID.parse("1.2.3.4.5.6")
        varbind = VarBind(oid, Integer(123456))

        handle = manager.get(oid, securityLevel=authNoPriv)
        self.assertRaises(
            IncomingMessageError,
            self.respond,
            pcap.messages.pop(),
            varbind,
            securityLevel=noAuthNoPriv,
        )

        handle = manager.get(oid, securityLevel=authPriv)
        self.assertRaises(
            IncomingMessageError,
            self.respond,
            pcap.messages.pop(),
            varbind,
            securityLevel=noAuthNoPriv,
        )

        handle = manager.get(oid, securityLevel=authPriv)
        self.assertRaises(
            IncomingMessageError,
            self.respond,
            pcap.messages.pop(),
            varbind,
            securityLevel=authNoPriv,
        )

    def test_IncomingMessageError_if_contextEngineID_does_not_match(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        reply = SNMPv3Message(
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
                b"wrong",
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            message.securityName,
        )

        self.assertRaises(IncomingMessageError, self.incoming.send, reply)

    def test_context_argument_is_used_for_the_scopedPDU_contextName(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", context=b"test case")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.assertEqual(message.scopedPDU.contextName, b"test case")

    def test_IncomingMessageError_if_incoming_contextName_does_not_match(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6", context=b"A")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        reply = SNMPv3Message(
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
                b"B",
            ),
            b"remote",
            SecurityName(self.userName, self.namespace),
        )

        self.assertRaises(IncomingMessageError, self.incoming.send, reply)
        self.assertRaises(Timeout, handle.wait)

    def test_IncomingMessageError_if_securityEngineID_does_not_match(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        reply = SNMPv3Message(
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
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            b"wrong",
            message.securityName,
        )

        self.assertRaises(IncomingMessageError, self.incoming.send, reply)

    def test_IncomingMessageError_if_securityName_does_not_match(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        reply = SNMPv3Message(
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
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            SecurityName(b"wrong", self.namespace),
        )

        self.assertRaises(IncomingMessageError, self.incoming.send, reply)

    def test_namespace_does_not_matter_for_noAuth_requests(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        reply = SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(),
                message.header.securityModel,
            ),
            ScopedPDU(
                ResponsePDU(
                    VarBind("1.2.3.4.5.6", Integer(123456)),
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            SecurityName(self.userName, "wrong"),
        )

        self.incoming.send(reply)
        vblist = handle.wait()
        self.assertEqual(len(vblist), 1)

    def test_IncomingMessageError_if_namespace_does_not_match_for_auth_request(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        reply = SNMPv3Message(
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
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            SecurityName(self.userName, "wrong"),
        )

        self.assertRaises(IncomingMessageError, self.incoming.send, reply)

    def test_namespace_does_not_matter_for_noAuth_request_even_if_response_has_auth(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")

        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        reply = SNMPv3Message(
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
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            SecurityName(self.userName, "wrong"),
        )

        self.incoming.send(reply)
        vblist = handle.wait()
        self.assertEqual(len(vblist), 1)

    def test_request_with_wait_raises_Timeout_if_there_is_no_response(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        self.assertRaises(Timeout, manager.get, "1.2.3.4.5.6", wait=True)

    def test_request_with_wait_returns_the_result_of_handle_wait(self):
        pcap = self.connect(PacketCapture())
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        respondTask = RespondTask(self, pcap, varbind)
        self.scheduler.schedule(respondTask, 1/4)

        manager = self.makeManager(engineID=b"remote")
        vblist = manager.get("1.2.3.4.5.6", wait=True)
        self.assertEqual(vblist[0], varbind)
        self.assertEqual(self.time(), 1/4)

    def test_request_with_autowait_raises_Timeout_if_there_is_no_response(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote", autowait=True)
        self.assertRaises(Timeout, manager.get, "1.2.3.4.5.6")

    def test_request_with_autowait_returns_the_result_of_handle_wait(self):
        pcap = self.connect(PacketCapture())
        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        respondTask = RespondTask(self, pcap, varbind)
        self.scheduler.schedule(respondTask, 1/4)

        manager = self.makeManager(engineID=b"remote", autowait=True)
        vblist = manager.get("1.2.3.4.5.6")
        self.assertEqual(vblist[0], varbind)
        self.assertEqual(self.time(), 1/4)

    def test_IncomingMessageError_if_request_handle_has_been_deactivated(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        varbind = VarBind("1.2.3.4.5.6", Integer(123456))
        self.respond(message, varbind)

        self.assertRaisesRegex(
            IncomingMessageError,
            "[Rr]equest",
            self.respond,
            message,
            varbind,
            securityLevel=noAuthNoPriv,
        )

    def test_handle_raises_ErrorResponse_if_errorStatus_is_nonzero(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.respond(
            message,
            message.scopedPDU.pdu.variableBindings[0],
            errorStatus=ErrorStatus.noAccess,
            errorIndex=1,
        )

        try:
            handle.wait()
        except ErrorResponse as err:
            varbind = message.scopedPDU.pdu.variableBindings[0]
            self.assertEqual(err.cause, varbind)
        else:
            self.assertTrue(False)

    def test_ErrorResponse_cause_is_request_pdu_if_errorIndex_is_zero(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.respond(
            message,
            message.scopedPDU.pdu.variableBindings[0],
            errorStatus=ErrorStatus.tooBig,
            errorIndex=0,
        )

        try:
            handle.wait()
        except ErrorResponse as err:
            self.assertEqual(err.cause, message.scopedPDU.pdu)
        else:
            self.assertTrue(False)

    def test_ErrorResponse_cause_is_errorIndex_if_out_of_range(self):
        pcap = self.connect(PacketCapture())
        manager = self.makeManager(authNoPriv, engineID=b"remote")
        handle = manager.get("1.2.3.4.5.6")
        self.assertEqual(len(pcap.messages), 1)
        message = pcap.messages.pop()

        self.respond(
            message,
            message.scopedPDU.pdu.variableBindings[0],
            errorStatus=ErrorStatus.noAccess,
            errorIndex=2,
        )

        try:
            handle.wait()
        except ErrorResponse as err:
            self.assertEqual(err.cause, 2)
        else:
            self.assertTrue(False)

# TODO: VarBindList OIDs don't match
# TODO: Verify handle ownership
# TODO: Test getNext, getBulk, and set
# TODO: Add withEngineID to ScopedPDU and SNMPv3Message

if __name__ == "__main__":
    unittest.main(verbosity=2)
