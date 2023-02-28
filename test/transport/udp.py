__all__ = [
    "UdpIPv4SocketTest", "UdpIPv6SocketTest",
    "UdpIPv4TransportTest", "UdpIPv6TransportTest",
]

import socket
from threading import Event, Thread
import time
import unittest

from snmp.transport import TransportListener
from snmp.transport.udp import UdpIPv4Socket, UdpIPv6Socket
from snmp.transport.udp import UdpIPv4Transport, UdpIPv6Transport

from snmp.transport.generic.udp import (
    UdpIPv4Transport as GenericUdpIPv4Transport,
    UdpIPv6Transport as GenericUdpIPv6Transport,
)

def declareUdpSocketTest(socketType, testAddress):
    class AbstractUdpSocketTest(unittest.TestCase):
        def setUp(self):
            self.addr = testAddress
            self.port = 2945

        def testAddressWithoutPort(self):
            addr, port = socketType.normalizeAddress(self.addr)
            self.assertEqual(addr, self.addr)
            self.assertEqual(port, 161)

        def testNormalizeNoOp(self):
            addr, port = socketType.normalizeAddress((self.addr, self.port))
            self.assertEqual(addr, self.addr)
            self.assertEqual(port, self.port)

        def testInvalidAddress(self):
            addr = "invalid"
            self.assertRaises(ValueError, socketType.normalizeAddress, addr)

        def testInvalidPortNumber(self):
            addr = (self.addr, 0x10000)
            self.assertRaises(ValueError, socketType.normalizeAddress, addr)

        def testInvalidAddressType(self):
            addr = b"invalid"
            self.assertRaises(TypeError, socketType.normalizeAddress, addr)

        def testInvalidPortType(self):
            addr = (self.addr, str(self.port))
            self.assertRaises(TypeError, socketType.normalizeAddress, addr)

        def testDefaultConstruction(self):
            socket = socketType()
            socket.close()

        def testLoopback(self):
            socket = socketType(socketType.DOMAIN.loopback_address)
            socket.close()

    return AbstractUdpSocketTest

def declareUdpTransportTest(transportType, testAddress):
    class AbstractUdpTransportTest(unittest.TestCase):
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

        def getDestAddress(self):
            # Beware that this may break, as .socket is a private attribute
            return (self.localhost, self.transport.socket.getsockname()[1])

        def spawnThread(self):
            thread = Thread(
                target=self.transport.listen,
                args=(self.listener,),
                daemon=True,
            )

            thread.start()
            return thread

        def setUp(self):
            self.localhost = transportType.DOMAIN.loopback_address
            self.listener = self.Listener()
            self.timeout = 10e-3

            self.transport = transportType(self.localhost)

        def tearDown(self):
            self.transport.close()

        def testStop(self):
            thread = self.spawnThread()
            self.transport.stop()
            thread.join(timeout=self.timeout)
            self.assertFalse(thread.is_alive())

        def testHear(self):
            thread = self.spawnThread()
            self.transport.send(self.getDestAddress(), b"test")
            self.listener.wait(self.timeout)
            self.transport.stop()
            thread.join(timeout=self.timeout)
            self.assertTrue(self.listener.heard)

        def testRestart(self):
            self.testHear()
            self.listener.reset()
            self.assertFalse(self.listener.heard)
            self.testHear()

    return AbstractUdpTransportTest

ipv4TestAddr = "12.84.238.117"
ipv6TestAddr = "18:6:249:132:81::25:7"

UdpIPv4SocketTest = declareUdpSocketTest(UdpIPv4Socket, ipv4TestAddr)
UdpIPv6SocketTest = declareUdpSocketTest(UdpIPv6Socket, ipv6TestAddr)
UdpIPv4TransportTest = declareUdpTransportTest(UdpIPv4Transport, ipv4TestAddr)
UdpIPv6TransportTest = declareUdpTransportTest(UdpIPv6Transport, ipv6TestAddr)

if UdpIPv4Transport is not GenericUdpIPv4Transport:
    GenericUdpIPv4TransportTest = declareUdpTransportTest(
        GenericUdpIPv4Transport,
        ipv4TestAddr,
    )

    __all__.append("GenericUdpIPv4TransportTest")

if UdpIPv6Transport is not GenericUdpIPv6Transport:
    GenericUdpIPv6TransportTest = declareUdpTransportTest(
        GenericUdpIPv6Transport,
        ipv6TestAddr,
    )

    __all__.append("GenericUdpIPv6TransportTest")

if __name__ == "__main__":
    unittest.main()
