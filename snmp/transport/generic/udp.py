__all__ = ["UdpMultiplexor"]

import select
from socket import *

from snmp.transport import *
from snmp.transport.udp import UdpSocket
from snmp.typing import *

STOPMSG = bytes(1)
RECV_SIZE = 65507

class GenericUdpMultiplexor(TransportMultiplexor[UdpSocket]):
    def __init__(self) -> None:
        self.r = None
        self.w = None
        self.sockets: Dict[int, UdpSocket] = {}

    def register(self, sock: UdpSocket) -> None:
        if self.w is None:
            address_family = sock.DOMAIN.address_family
            loopback_address = sock.DOMAIN.loopback_address

            self.r = socket(address_family, SOCK_DGRAM)
            self.w = socket(address_family, SOCK_DGRAM)

            self.r.setblocking(False)
            self.r.bind((loopback_address, 0))
            self.w.bind((loopback_address, 0))

        self.sockets[sock.fileno] = sock

    def listen(self, listener: TransportListener) -> None:
        readfds = []

        if self.r is not None:
            readfds.append(self.r.fileno())

        for fileno in self.sockets.keys():
            readfds.append(fileno)

        done = not readfds
        while not done:
            ready = select.select(readfds, [], [])[0]
            for fd in ready:
                try:
                    sock = self.sockets[fd]
                except KeyError:
                    if fd == self.r.fileno():
                        data, addr = self.r.recvfrom(len(STOPMSG))
                        done = addr == self.w.getsockname() and data == STOPMSG
                else:
                    addr, data = sock.receive(RECV_SIZE)
                    listener.hear(sock, addr, data)

    def stop(self) -> None:
        if self.w is not None:
            self.w.sendto(STOPMSG, self.r.getsockname())

    def close(self) -> None:
        for sock in self.sockets.values():
            sock.close()

        if self.w is not None:
            self.w.close()
            self.r.close()

UdpMultiplexor = GenericUdpMultiplexor
