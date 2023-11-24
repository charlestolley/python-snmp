__all__ = ["UdpMultiplexor"]

import select
from socket import *

from snmp.transport import *
from snmp.transport.udp import UdpSocket
from snmp.typing import *

STOPMSG = bytes(1)

class GenericUdpMultiplexor(TransportMultiplexor[Tuple[str, int]]):
    def __init__(self, recvSize: int = 1472) -> None:
        self.recvSize = recvSize
        self.r: Optional[socket] = None
        self.w: Optional[socket] = None
        self.sockets: Dict[int, UdpSocket] = {}

    def register(self, sock: UdpSocket) -> None:    # type: ignore[override]
        if self.w is None:
            address_family = sock.DOMAIN.address_family
            loopback_address = sock.DOMAIN.loopback_address

            self.r = socket(address_family, SOCK_DGRAM)
            self.w = socket(address_family, SOCK_DGRAM)

            self.r.setblocking(False)
            self.r.bind((loopback_address, 0))
            self.w.bind((loopback_address, 0))

        self.sockets[sock.fileno] = sock

    def listen(self, listener: TransportListener[Tuple[str, int]]) -> None:
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
                    assert self.r is not None
                    assert self.w is not None
                    if fd == self.r.fileno():
                        data, addr = self.r.recvfrom(len(STOPMSG))
                        done = addr == self.w.getsockname() and data == STOPMSG
                else:
                    addr, data = sock.receive(self.recvSize)
                    listener.hear(sock, addr, data)

    def stop(self) -> None:
        if self.w is not None:
            assert self.r is not None
            self.w.sendto(STOPMSG, self.r.getsockname())

    def close(self) -> None:
        for sock in self.sockets.values():
            sock.close()

        if self.w is not None:
            assert self.r is not None
            self.w.close()
            self.r.close()

UdpMultiplexor = GenericUdpMultiplexor
