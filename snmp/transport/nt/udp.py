__all__ = ["UdpTransport"]

import os
import select
import socket

from ..udp import UdpTransportBase
from snmp.utils import typename

RECV_SIZE = 65507

class UdpTransport(UdpTransportBase):
    def __init__(self, host="", port=0):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.r      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.w      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.socket.setblocking(False)
        self.r     .setblocking(False)

        self.socket.bind((host, port))
        self.r.bind(("127.0.0.1", 0))
        self.w.bind(("127.0.0.1", 0))

    def close(self):
        self.w.close()
        self.r.close()
        self.socket.close()

    def listen(self, listener):
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
                    data, addr = self.r.recvfrom(1)
                    if data == b"\0" and addr == self.w.getsockname():
                        done = True

    def send(self, addr, packet):
        self.socket.sendto(packet, addr)

    def stop(self):
        self.w.sendto(b"\0", self.r.getsockname())
