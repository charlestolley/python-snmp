__all__ = ["TransportChannelTest"]

import unittest

from snmp.transport import *
from snmp.utils import typename

class FakeTransport:
    DOMAIN = TransportDomain.UDP_IPv4

    def __eq__(self, other):
        return type(self) == type(other)

    def __repr__(self):
        return f"{typename(self)}()"

    @property
    def recvSize(self):
        return 1234

class TransportChannelTest(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.channel = TransportChannel(self.transport, ("127.0.0.1", 161))

    def test_domain_returns_Transport_DOMAIN(self):
        self.assertEqual(self.channel.domain, TransportDomain.UDP_IPv4)

    def test_msgMaxSize_returns_Transport_recvSize(self):
        self.assertEqual(self.channel.msgMaxSize, 1234)

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        duplicate = eval(repr(self.channel))
        self.assertEqual(duplicate.transport, self.transport)
        self.assertEqual(duplicate.address, self.channel.address)
