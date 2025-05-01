__all__ = ["UdpMultiplexor"]

import select
import socket

from snmp.transport import *
from snmp.transport.udp import UdpListener, UdpSocket
from snmp.typing import *

STOPMSG = bytes(1)

class GenericUdpMultiplexor(TransportMultiplexor[Tuple[str, int]]):
    def __init__(self, recvSize: int = 1472) -> None:
        self.recvSize = recvSize
        self.sockets: Dict[int, Tuple[UdpSocket, UdpListener]] = {}

        domain = TransportDomain.UDP_IPv4
        self.r = socket.socket(domain.address_family, socket.SOCK_DGRAM)
        self.w = socket.socket(domain.address_family, socket.SOCK_DGRAM)

        self.r.setblocking(False)
        self.r.bind((domain.loopback_address, 0))
        self.w.bind((domain.loopback_address, 0))

        self.readfds = [self.r.fileno()]

    def register(self, sock: UdpSocket, listener: UdpListener) -> None:
        self.readfds.append(sock.fileno)
        self.sockets[sock.fileno] = sock, listener

    def poll(self, timeout: Optional[float] = None) -> bool:
        interrupted = False

        if self.readfds:
            ready = select.select(self.readfds, [], [], timeout)[0]
            for fd in ready:
                try:
                    sock, listener = self.sockets[fd]
                except KeyError:
                    if fd == self.r.fileno():
                        data, addr = self.r.recvfrom(len(STOPMSG))
                        if addr == self.w.getsockname() and data == STOPMSG:
                            interrupted = True
                else:
                    addr, data = sock.receive(self.recvSize)
                    listener.hear(data, TransportChannel(sock, addr))

        return interrupted

    def stop(self) -> None:
        if self.w is not None:
            self.w.sendto(STOPMSG, self.r.getsockname())

    def close(self) -> None:
        for sock, _ in self.sockets.values():
            sock.close()

        if self.w is not None:
            self.w.close()
            self.r.close()

UdpMultiplexor = GenericUdpMultiplexor
