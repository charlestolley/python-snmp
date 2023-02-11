__all__ = ["UdpTransportTest"]

import socket
from threading import Event, Thread
import time
import unittest

from snmp.transport import TransportListener
from snmp.transport.udp import UdpTransport
from snmp.transport.generic.udp import UdpTransport as GenericUdpTransport

def declareUdpTransportTest(transportType):
    class AbstractUdpTransportTest(unittest.TestCase):
        class Listener(TransportListener):
            def __init__(self):
                self.event = Event()

            @property
            def heard(self):
                return self.event.is_set()

            def hear(self, transport, addr, data):
                self.event.set()

            def wait(self, timeout):
                self.event.wait(timeout=timeout)

        def setUp(self):
            self.addr = "12.84.238.117"
            self.localhost = "127.0.0.1"
            self.port = 2945
            self.listener = self.Listener()
            self.timeout = 10e-3

            self.transport = transportType(self.localhost)
            self.thread = Thread(
                target=self.transport.listen,
                args=(self.listener,),
                daemon=True,
            )

        def tearDown(self):
            self.transport.close()

        def testAddressWithoutPort(self):
            addr, port = self.transport.normalizeAddress(self.addr)
            self.assertEqual(addr, self.addr)
            self.assertEqual(port, 161)

        def testNormalizeNoOp(self):
            addr, port = self.transport.normalizeAddress((self.addr, self.port))
            self.assertEqual(addr, self.addr)
            self.assertEqual(port, self.port)

        def testInvalidAddress(self):
            addr = "invalid"
            self.assertRaises(ValueError, self.transport.normalizeAddress, addr)

        def testInvalidPortNumber(self):
            addr = (self.addr, 0x10000)
            self.assertRaises(ValueError, self.transport.normalizeAddress, addr)

        def testInvalidAddressType(self):
            addr = socket.inet_pton(socket.AF_INET, self.addr)
            self.assertRaises(TypeError, self.transport.normalizeAddress, addr)

        def testInvalidPortType(self):
            addr = (self.addr, str(self.port))
            self.assertRaises(TypeError, self.transport.normalizeAddress, addr)

        def testStop(self):
            self.thread.start()
            self.transport.stop()
            self.thread.join(timeout=self.timeout)
            self.assertFalse(self.thread.is_alive())

        def testHear(self):
            self.thread.start()

            # Beware that this may break, as .socket is a private attribute
            addr = (self.localhost, self.transport.socket.getsockname()[1])

            self.transport.send(addr, b"test")
            self.listener.wait(self.timeout)
            self.transport.stop()
            self.thread.join(timeout=self.timeout)
            self.assertTrue(self.listener.heard)

    return AbstractUdpTransportTest

UdpTransportTest = declareUdpTransportTest(UdpTransport)

if UdpTransport is not GenericUdpTransport:
    GenericUdpTransportTest = declareUdpTransportTest(GenericUdpTransport)
    __all__.append("GenericUdpTransportTest")

if __name__ == "__main__":
    unittest.main()
