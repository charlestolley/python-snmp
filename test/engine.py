__all__ = [
    "SNMPv3ManagerAddUserTest", "SNMPv3ManagerNoAddUserTest",
    "EngineTest",
]

import unittest

from snmp.engine import *
from snmp.message.version import *
from snmp.security.levels import *
from snmp.transport import TransportDomain

from test.security.usm import DummyAuthProtocol

class FakeUdpIPv4Socket:
    def __init__(self, *args, mtu=9423116, **kwargs):
        self.address = None
        self.data = None
        self.mtu = mtu

    @classmethod
    def normalizeAddress(self, *args, **kwargs):
        return UdpIPv4Socket.normalizeAddress(*args, **kwargs)

    def send(self, data, address):
        self.address = address
        self.data = data

class FakeUdpIPv6Socket:
    def __init__(self, *args, **kwargs):
        pass

    @classmethod
    def normalizeAddress(self, *args, **kwargs):
        return UdpIPv6Socket.normalizeAddress(*args, **kwargs)

class FakeMultiplexor:
    def poll(timeout=None):
        return False

    def register(self, transport, listener):
        pass

TRANSPORTS = {
    TransportDomain.UDP_IPv4: FakeUdpIPv4Socket,
}

class SNMPv3ManagerNoAddUserTest(unittest.TestCase):
    def setUp(self):
        self.mux = FakeMultiplexor()
        self.engine = Engine(multiplexor=self.mux)
        self.engine.TRANSPORTS = TRANSPORTS
        self.addr = "127.0.0.1"
        self.user = "chuck"

    def test_no_addUser_no_defaultUser_raises_TypeError(self):
        self.assertRaises(TypeError, self.engine.Manager, self.addr)

    def test_no_addUser_no_defaultUser_includes_namespace_in_error_msg(self):
        self.assertRaisesRegex(
            TypeError,
            r"users in namespace \"asdf\" by calling addUser",
            self.engine.Manager,
            "127.0.0.1",
            namespace="asdf",
        )

    def test_defaultUser_without_addUser_defaults_to_noAuthNoPriv(self):
        manager = self.engine.Manager(self.addr, defaultUser=self.user)
        self.assertEqual(manager.defaultSecurityLevel, noAuthNoPriv)

    def test_defaultUser_without_addUser_accepts_noAuthNoPriv(self):
        manager = self.engine.Manager(
            self.addr,
            defaultUser=self.user,
            defaultSecurityLevel=noAuthNoPriv,
        )

        self.assertEqual(manager.defaultSecurityLevel, noAuthNoPriv)

    def test_defaultUser_without_addUser_ValueError_for_authNoPriv(self):
        self.assertRaises(
            ValueError,
            self.engine.Manager,
            self.addr,
            defaultUser=self.user,
            defaultSecurityLevel=authNoPriv,
        )

    def test_defaultUser_without_addUser_authNoPriv_namesp_in_error_msg(self):
        self.assertRaisesRegex(
            ValueError,
            r"\"testuser\" in namespace \"asdf\" does not",
            self.engine.Manager,
            "127.0.0.1",
            namespace="asdf",
            defaultUser="testuser",
            defaultSecurityLevel=authNoPriv,
        )

class SNMPv3ManagerAddUserTest(unittest.TestCase):
    def setUp(self):
        self.mux = FakeMultiplexor()
        self.engine = Engine(multiplexor=self.mux)
        self.engine.TRANSPORTS = TRANSPORTS

        self.addr = "127.0.0.1"
        self.user = "chuck"
        self.otherUser = "other"

        self.engine.addUser(
            self.user,
            authProtocol=DummyAuthProtocol,
            authSecret=b"asdf",
        )

        self.engine.addUser(self.otherUser)

    def test_defaultUser_and_defaultSecurityLevel_inferred_from_addUser(self):
        manager = self.engine.Manager(self.addr)
        self.assertEqual(manager.defaultUserName, self.user.encode())
        self.assertEqual(manager.defaultSecurityLevel, authNoPriv)

    def test_defaultSecurityLevel_inferred_from_defaultUser(self):
        manager = self.engine.Manager(self.addr, defaultUser = self.otherUser)
        self.assertEqual(manager.defaultUserName, self.otherUser.encode())
        self.assertEqual(manager.defaultSecurityLevel, noAuthNoPriv)

    def test_no_defaultUser_ValueError_if_defaultSecurityLevel_too_high(self):
        self.assertRaises(
            ValueError,
            self.engine.Manager,
            self.addr,
            defaultSecurityLevel = authPriv,
        )

    def test_ValueError_if_defaultSecurityLevel_is_too_high(self):
        self.assertRaises(
            ValueError,
            self.engine.Manager,
            self.addr,
            defaultUser = self.otherUser,
            defaultSecurityLevel = authNoPriv,
        )

    def test_a_second_call_to_addUser_overrides_the_first_one(self):
        self.engine.addUser(
            self.otherUser,
            authProtocol=DummyAuthProtocol,
            authSecret=b"fdsa",
        )

        manager = self.engine.Manager(
            self.addr,
            defaultUser = self.otherUser,
            defaultSecurityLevel = authNoPriv,
        )

class EngineTest(unittest.TestCase):
    def setUp(self):
        self.mux = FakeMultiplexor()
        self.engine = Engine(multiplexor=self.mux)
        self.engine.TRANSPORTS = TRANSPORTS

    def test_invalid_ctor_kwarg_does_not_cause_AttributeError_in_dtor(self):
        # we can't assign the new Engine to a variable because the constructor
        # raises a TypeError, but the interpreter keeps a reference to it
        # somewhere, and when it's finally cleaned up, we want to be sure that
        # the __del__() method does not raise an AttributeError
        self.assertRaises(TypeError, Engine, asdf=4)

    def test_Manager_raises_ValueError_for_invalid_domain(self):
        self.assertRaisesRegex(
            ValueError,
            r"[Dd]omain",
            self.engine.Manager,
            "::1",
            domain=TransportDomain.UDP_IPv6,
        )

    def test_Manager_forwards_mtu_argument_to_transport_ctor(self):
        manager = self.engine.Manager("127.0.0.1", defaultUser="", mtu=900)
        self.assertEqual(manager.channel.transport.mtu, 900)

    def test_Manager_omits_mtu_argument_from_transport_ctor_when_None(self):
        manager = self.engine.Manager("127.0.0.1", defaultUser="")
        self.assertEqual(manager.channel.transport.mtu, 9423116)

    def test_Manager_allows_integer_version_argument(self):
        manager = self.engine.Manager("127.0.0.1", version=3, defaultUser="u")

    def test_Manager_raises_ValueError_for_invalid_integer_version(self):
        self.assertRaises(
            ValueError,
            self.engine.Manager,
            "127.0.0.1",
            version=4,
            defaultUser="testuser"
        )

    def test_SNMPv1_Manager_sends_SNMPv1_messages(self):
        manager = self.engine.Manager(
            "127.0.0.1",
            version=ProtocolVersion.SNMPv1,
            autowait=False,
        )

        handle = manager.get("1.3.6.1.2.1.1.1.0")
        transport = manager.channel.transport
        self.assertEqual(transport.address, ("127.0.0.1", 161))

        msg = VersionOnlyMessage.decodeExact(transport.data)
        self.assertEqual(msg.version, ProtocolVersion.SNMPv1)

    def test_SNMPv2c_Manager_sends_SNMPv2c_messages(self):
        manager = self.engine.Manager(
            "127.0.0.1",
            version=ProtocolVersion.SNMPv2c,
            autowait=False,
        )

        handle = manager.get("1.3.6.1.2.1.1.1.0")
        transport = manager.channel.transport
        self.assertEqual(transport.address, ("127.0.0.1", 161))

        msg = VersionOnlyMessage.decodeExact(transport.data)
        self.assertEqual(msg.version, ProtocolVersion.SNMPv2c)

if __name__ == "__main__":
    unittest.main()
