__all__ = ["UdpMultiplexor"]

import os
import select

from snmp.transport import *
from snmp.transport.udp import UdpSocket
from snmp.typing import *

class PosixUdpMultiplexor(TransportMultiplexor[Tuple[str, int]]):
    def __init__(self, recvSize: int = 1472) -> None:
        self.recvSize = recvSize
        self.r, self.w = os.pipe()
        self.sockets: Dict[int, UdpSocket] = {}

    def register(self, sock: UdpSocket) -> None:    # type: ignore[override]
        self.sockets[sock.fileno] = sock

    def listen(self, listener: TransportListener[Tuple[str, int]]) -> None:
        poller = select.poll()
        poller.register(self.r, select.POLLIN)

        for fileno in self.sockets.keys():
            poller.register(fileno, select.POLLIN)

        done = False
        while not done:
            ready = poller.poll()
            for fd, _ in ready:
                try:
                    sock = self.sockets[fd]
                except KeyError:
                    if fd == self.r:
                        os.read(fd, 1)
                        done = True
                else:
                    addr, data = sock.receive(self.recvSize)
                    listener.hear(sock, addr, data)

    def stop(self) -> None:
        os.write(self.w, bytes(1))

    def close(self) -> None:
        for sock in self.sockets.values():
            sock.close()

        os.close(self.w)
        os.close(self.r)

UdpMultiplexor = PosixUdpMultiplexor
