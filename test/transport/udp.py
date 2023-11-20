__all__ = ["UdpIPv4SocketTest", "UdpIPv6SocketTest", "UdpMultiplexorTest"]

import socket
from threading import Event, Thread
import time
import unittest

from snmp.transport import AddressUsage, TransportListener
from snmp.transport.udp import UdpIPv4Socket, UdpIPv6Socket, UdpMultiplexor

from snmp.transport.generic.udp import (
    UdpMultiplexor as GenericUdpMultiplexor,
)

def declareUdpSocketTest(socketType, testAddress):
    class AbstractUdpSocketTest(unittest.TestCase):
        def setUp(self):
            self.addr = testAddress
            self.port = 2945

        def testAddressWithoutPort(self):
            addr, port = socketType.normalizeAddress(self.addr)
            self.assertEqual(addr, self.addr)
            self.assertEqual(port, 0)

        def testDefaultListenPort(self):
            addr, port = socketType.normalizeAddress(
                self.addr,
                AddressUsage.LISTENER,
            )

            self.assertEqual(addr, self.addr)
            self.assertEqual(port, 161)

        def testDefaultSendPort(self):
            addr, port = socketType.normalizeAddress(
                self.addr,
                AddressUsage.SENDER,
            )

            self.assertEqual(addr, self.addr)
            self.assertEqual(port, 0)

        def testDefaultTrapListenPort(self):
            addr, port = socketType.normalizeAddress(
                self.addr,
                AddressUsage.TRAP_LISTENER,
            )

            self.assertEqual(addr, self.addr)
            self.assertEqual(port, 162)

        def testNormalizeNoOp(self):
            addr, port = socketType.normalizeAddress((self.addr, self.port))
            self.assertEqual(addr, self.addr)
            self.assertEqual(port, self.port)

        def testNoAddress(self):
            addr, port = socketType.normalizeAddress()
            self.assertEqual(addr, socketType.DOMAIN.default_address)
            self.assertEqual(port, 0)

        def testEmptyListenerAddress(self):
            self.assertRaises(
                ValueError,
                socketType.normalizeAddress,
                "",
                AddressUsage.LISTENER
            )

        def testEmptySenderAddress(self):
            addr, port = socketType.normalizeAddress(
                "",
                AddressUsage.SENDER,
            )

            self.assertEqual(addr, socketType.DOMAIN.default_address)

        def testEmptyTrapListenerAddress(self):
            self.assertRaises(
                ValueError,
                socketType.normalizeAddress,
                "",
                AddressUsage.TRAP_LISTENER
            )

        def testInvalidAddress(self):
            addr = "invalid"
            self.assertRaises(ValueError, socketType.normalizeAddress, addr)

        def testInvalidPortNumber(self):
            addr = (self.addr, 0x10000)
            self.assertRaises(ValueError, socketType.normalizeAddress, addr)

        def testInvalidAddressType(self):
            addr = (b"invalid", 1)
            self.assertRaises(TypeError, socketType.normalizeAddress, addr)

        def testInvalidPortType(self):
            addr = (self.addr, str(self.port))
            self.assertRaises(TypeError, socketType.normalizeAddress, addr)

        def testDefaultConstruction(self):
            sock = socketType()
            sock.close()

        def testLoopback(self):
            sock = socketType(socketType.DOMAIN.loopback_address)
            sock.close()

    return AbstractUdpSocketTest

def declareUdpMultiplexorTest(Multiplexor):
    class UdpMultiplexorTest(unittest.TestCase):
        class Listener(TransportListener):
            def __init__(self):
                self.event = Event()

            @property
            def heard(self):
                return self.event.is_set()

            def hear(self, transport, addr, data):
                self.event.set()

            def reset(self):
                self.event.clear()

            def wait(self, timeout):
                self.event.wait(timeout=timeout)

        def setUp(self):
            self.listener = self.Listener()
            self.timeout = 10e-3

            self.multiplexor = Multiplexor()

        def spawnThread(self):
            thread = Thread(
                target=self.multiplexor.listen,
                args=(self.listener,),
                daemon=True,
            )

            thread.start()
            return thread

        def tearDown(self):
            self.multiplexor.close()

        def testRegisterMultiple(self):
            self.multiplexor.register(UdpIPv4Socket())
            self.multiplexor.register(UdpIPv4Socket())
            self.multiplexor.register(UdpIPv6Socket())
            self.multiplexor.register(UdpIPv6Socket())

        def testStop(self):
            self.multiplexor.register(UdpIPv4Socket())
            self.multiplexor.register(UdpIPv6Socket())

            thread = self.spawnThread()
            self.multiplexor.stop()
            thread.join(timeout=self.timeout)
            self.assertFalse(thread.is_alive())

        def testHearIPv4(self):
            sock = UdpIPv4Socket()
            self.multiplexor.register(sock)

            thread = self.spawnThread()
            sock.send((sock.DOMAIN.loopback_address, sock.port), b"IPv4 test")
            self.listener.wait(self.timeout)
            self.multiplexor.stop()
            thread.join(timeout=self.timeout)

            self.assertTrue(self.listener.heard)

        def testHearIPv6(self):
            sock = UdpIPv6Socket()
            self.multiplexor.register(sock)

            thread = self.spawnThread()
            sock.send((sock.DOMAIN.loopback_address, sock.port), b"IPv6 test")
            self.listener.wait(self.timeout)
            self.multiplexor.stop()
            thread.join(timeout=self.timeout)

            self.assertTrue(self.listener.heard)

        def testRestart(self):
            self.testHearIPv4()
            self.listener.reset()
            self.assertFalse(self.listener.heard)
            self.testHearIPv6()

        def testInterruption(self):
            ipv4 = UdpIPv4Socket()
            self.multiplexor.register(ipv4)

            thread = self.spawnThread()
            self.multiplexor.stop()
            thread.join(timeout=self.timeout)

            addr = (ipv4.DOMAIN.loopback_address, ipv4.port)
            ipv4.send(addr, b"Interruption test")
            self.listener.wait(self.timeout)
            self.assertFalse(self.listener.heard)

            ipv6 = UdpIPv6Socket()
            self.multiplexor.register(ipv6)

            thread = self.spawnThread()
            self.listener.wait(self.timeout)
            self.multiplexor.stop()
            thread.join(timeout=self.timeout)

            self.assertTrue(self.listener.heard)

    return UdpMultiplexorTest

ipv4TestAddr = "12.84.238.117"
ipv6TestAddr = "18:6:249:132:81::25:7"

UdpIPv4SocketTest = declareUdpSocketTest(UdpIPv4Socket, ipv4TestAddr)
UdpIPv6SocketTest = declareUdpSocketTest(UdpIPv6Socket, ipv6TestAddr)
UdpMultiplexorTest = declareUdpMultiplexorTest(UdpMultiplexor)

if UdpMultiplexor is not GenericUdpMultiplexor:
    GenericUdpMultiplexorTest = \
        declareUdpMultiplexorTest(GenericUdpMultiplexor)

    __all__.append("GenericUdpMultiplexorTest")

if __name__ == "__main__":
    unittest.main()
