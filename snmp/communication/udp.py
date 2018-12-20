import socket
from threading import Thread
import time

PORT = 161
RECV_SIZE = 65507

class UDP:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0))

    def __del__(self):
        self.sock.close()

    def send(self, host, message):
        self.sock.sendto(message, (host, PORT))

    def recv(self):
        msg, (host, port) = self.sock.recvfrom(RECV_SIZE)
        return msg
