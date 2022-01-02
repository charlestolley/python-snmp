__all__ = ["UdpTransport"]

import os
import select
import socket

RECV_SIZE = 65507

class UdpTransport:
    def __init__(self, listener, host="", port=0):
        self.listener = listener
        self.pipe = os.pipe()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        self.socket.bind((host, port))

    def close(self):
        os.close(self.pipe[0])
        os.close(self.pipe[1])
        self.socket.close()

    def listen(self):
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
                    self.listener.hear(addr, data)
                elif fd == abort:
                    os.read(fd, 1)
                    done = True

    def send(self, addr, packet):
        self.socket.sendto(packet, addr)

    def stop(self):
        os.write(self.pipe[1], b'\0')
