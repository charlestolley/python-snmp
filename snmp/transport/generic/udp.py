__all__ = ["UdpTransport"]

import os
import select
import socket

from snmp.transport import TransportListener
from snmp.transport.udp import UdpTransportBase
from snmp.typing import *

STOPMSG = bytes(1)
RECV_SIZE = 65507

class UdpTransport(UdpTransportBase):
    def __init__(self, host: str = "", port: int = 0) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.r      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.w      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.socket.setblocking(False)
        self.r     .setblocking(False)

        self.socket.bind((host, port))
        self.r.bind(("127.0.0.1", 0))
        self.w.bind(("127.0.0.1", 0))

    def close(self) -> None:
        self.w.close()
        self.r.close()
        self.socket.close()

    def listen(self, listener: TransportListener) -> None:
        sock = self.socket.fileno()
        stop = self.r.fileno()

        done = False
        while not done:
            ready = select.select([sock, stop], [], [])[0]
            for fd in ready:
                if fd == sock:
                    data, addr = self.socket.recvfrom(RECV_SIZE)
                    listener.hear(self, addr, data)
                elif fd == stop:
                    data, addr = self.r.recvfrom(len(STOPMSG))
                    if addr == self.w.getsockname() and data == STOPMSG:
                        done = True

    def send(self, addr: Tuple[str, int], packet: bytes) -> None:
        self.socket.sendto(packet, addr)

    def stop(self) -> None:
        self.w.sendto(STOPMSG, self.r.getsockname())
