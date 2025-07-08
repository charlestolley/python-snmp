__all__ = [
    "AddressUsage", "Transport", "TransportChannel",
    "TransportDomain", "TransportListener", "TransportMultiplexor"
]

import os

from enum import Enum
from socket import AF_INET, AF_INET6, AddressFamily

AddressUsage = Enum(
    "AddressUsage",
    ["LISTENER", "TRAP_LISTENER", "SENDER"]
)

class TransportDomain(Enum):
    def __init__(self, family, loopback, default):
        self.address_family = family
        self.loopback_address = loopback
        self.default_address = default

    UDP_IPv4 = AF_INET, "127.0.0.1", "0.0.0.0"
    UDP_IPv6 = AF_INET6, "::1", "::"

class Transport:
    @classmethod
    def normalizeAddress(cls, address = None, usage = None):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def send(self, data, address):
        raise NotImplementedError()

class TransportChannel:
    def __init__(self, transport, address):
        self.transport = transport
        self.address = address

    @property
    def domain(self):
        return self.transport.DOMAIN

    @property
    def msgMaxSize(self):
        return self.transport.recvSize

    def send(self, data):
        self.transport.send(data, self.address)

class TransportListener:
    def hear(self, data, channel):
        raise NotImplementedError()

class TransportMultiplexor:
    def register(self, sock, listener):
        raise NotImplementedError()

    def listen(self):
        done = False
        while not done:
            done = self.poll()

    def poll(self, timeout = None):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

supported = ("posix")
if os.name in supported:
    package = os.name
else:
    package = "generic"

package = "{}.{}".format(__name__, package)
