__all__ = ["UdpMultiplexor"]

import math
import os
import select

from snmp.transport import *
from snmp.transport.udp import UdpListener, UdpSocket
from snmp.typing import *

class PosixUdpMultiplexor(TransportMultiplexor[Tuple[str, int]]):
    def __init__(self, recvSize: int = 1472) -> None:
        self.recvSize = recvSize
        self.r, self.w = os.pipe()
        self.sockets: Dict[int, Tuple[UdpSocket, UdpListener]] = {}

        self.poller = select.poll()
        self.poller.register(self.r, select.POLLIN)

    def register(self, sock: UdpSocket, listener: UdpListener) -> None:
        self.sockets[sock.fileno] = sock, listener
        self.poller.register(sock.fileno, select.POLLIN)

    def poll(self, timeout: Optional[float] = None) -> bool:
        msecs = math.ceil(timeout * 1000) if timeout is not None else None

        interrupted = False
        ready = self.poller.poll(msecs)

        for fd, _ in ready:
            try:
                sock, listener = self.sockets[fd]
            except KeyError:
                if fd == self.r:
                    os.read(fd, 1)
                    interrupted = True
            else:
                addr, data = sock.receive(self.recvSize)
                listener.hear(sock, addr, data)

        return interrupted

    def stop(self) -> None:
        os.write(self.w, bytes(1))

    def close(self) -> None:
        for sock, _ in self.sockets.values():
            sock.close()

        os.close(self.w)
        os.close(self.r)

UdpMultiplexor = PosixUdpMultiplexor
