__all__ = ["UdpMultiplexor"]

import math
import os
import select

from snmp.transport import *

class PosixUdpMultiplexor(TransportMultiplexor):
    def __init__(self):
        self.r, self.w = os.pipe()
        self.sockets = {}

        self.poller = select.poll()
        self.poller.register(self.r, select.POLLIN)

    def register(self, sock, listener):
        self.sockets[sock.fileno] = sock, listener
        self.poller.register(sock.fileno, select.POLLIN)

    def poll(self, timeout = None):
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
                addr, data = sock.receive()
                listener.hear(data, TransportChannel(sock, addr))

        return interrupted

    def stop(self):
        os.write(self.w, bytes(1))

    def close(self):
        for sock, _ in self.sockets.values():
            sock.close()

        os.close(self.w)
        os.close(self.r)

UdpMultiplexor = PosixUdpMultiplexor
