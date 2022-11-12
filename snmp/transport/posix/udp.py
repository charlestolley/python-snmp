__all__ = ["UdpTransport"]

import os
import select
import socket

from snmp.transport import TransportListener
from snmp.transport.udp import UdpTransportBase
from snmp.typing import *

RECV_SIZE = 65507

class UdpTransport(UdpTransportBase):
    def __init__(self, host: str = "", port: int = 0) -> None:
        self.pipe = os.pipe()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
