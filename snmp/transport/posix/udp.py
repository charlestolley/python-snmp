__all__ = ["UdpIPv4Transport", "UdpIPv6Transport"]

import os
import select
import socket

from snmp.transport import *
from snmp.typing import *

RECV_SIZE = 65507

class PosixUdpTransport:
    def __init__(self, host: str = "", port: int = 0) -> None:
        self.pipe = os.pipe()

        address_family = self.DOMAIN.address_family
        self.socket = socket.socket(address_family, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        self.socket.bind((host, port))

    def close(self) -> None:
        os.close(self.pipe[0])
        os.close(self.pipe[1])
        self.socket.close()

    def listen(self, listener: TransportListener) -> None:
        abort = self.pipe[0]
        sock = self.socket.fileno()

        poller = select.poll()
        poller.register(sock, select.POLLIN)
        poller.register(abort, select.POLLIN)

        done = False
        while not done:
            ready = poller.poll()
            for fd, _ in ready:
                if fd == sock:
                    data, addr = self.socket.recvfrom(RECV_SIZE)
                    listener.hear(self, addr, data)
                elif fd == abort:
                    os.read(fd, 1)
                    done = True

    def send(self, addr: Tuple[str, int], packet: bytes) -> None:
        self.socket.sendto(packet, addr)

    def stop(self) -> None:
        os.write(self.pipe[1], bytes(1))

class UdpIPv4Transport(PosixUdpTransport):
    DOMAIN = TransportDomain.UDP_IPv4

class UdpIPv6Transport(PosixUdpTransport):
    DOMAIN = TransportDomain.UDP_IPv6
