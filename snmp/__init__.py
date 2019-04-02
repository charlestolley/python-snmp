import logging
import os
import random
import select
import socket
import threading
import time

from .exceptions import ProtocolError, Timeout, STATUS_ERRORS
from .types import *

log = logging.getLogger(__name__)

PORT = 161
RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff

def _listener(sock, data, lock, signal, done):
    while True:
        r, _, _ = select.select([sock, done], [], [])
        if done in r:
            return

        packet, (host, port) = sock.recvfrom(RECV_SIZE)
        if port != PORT:
            continue

        try:
            message = ASN1.deserialize(packet, cls=Message)

            if message.version != 0:
                continue

            message.poke()

        except (EncodingError, ProtocolError) as e:
            continue

        with lock:
            data[message.data.request_id.value] = message

        signal.set()

class Manager:
    def __init__(self, community=None, rwcommunity=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._sock.bind(('', 0))

        r, w = os.pipe()
        self._read_pipe = os.fdopen(r)
        self._write_pipe_fd = w

        self.rocommunity = community
        self.rwcommunity = rwcommunity or community

        # counting by an odd number should hit every request id once before repeating
        self._count_by = random.randint(0, MAX_REQUEST_ID//2) * 2 + 1
        self._next_id = self._count_by

        self._responses = {}
        self._lock = threading.Lock()
        self._received = threading.Event()

        self._listener = threading.Thread(
            target=_listener,
            args=(self._sock, self._responses, self._lock, self._received, self._read_pipe),
        )
        self._listener.start()

    def close(self):
        log.debug("Sending shutdown signal to listener thread")
        os.write(self._write_pipe_fd, b'\0')

        log.debug("Joining self._listener")
        self._listener.join()
        self._listener = None

        self._read_pipe.close()
        os.close(self._write_pipe_fd)
        self._sock.close()

    def __del__(self):
        if self._listener is not None:
            self.close()

    def _request_id(self):
        request_id = self._next_id
        self._next_id = (request_id + self._count_by) & MAX_REQUEST_ID

        return request_id

    def get(self, host, *oids, community=None):
        pdu = GetRequestPDU(
            request_id=self._request_id(),
            vars=VarBindList(*[VarBind(OID(oid), NULL()) for oid in oids]),
        )
        return self._request(host, pdu, community=community or self.rocommunity)

    def get_next(self, host, *oids, community=None):
        pdu = GetNextRequestPDU(
            request_id=self._request_id(),
            vars=VarBindList(*[VarBind(OID(oid), NULL()) for oid in oids]),
        )
        return self._request(host, pdu, community=community or self.rocommunity)

    def set(self, host, *nvpairs, community=None):
        varlist = []
        for oid, value in nvpairs:
            if isinstance(value, int):
                value = INTEGER(value)
            elif value == None:
                value = NULL()
            elif isinstance(value, ASN1):
                pass
            else:
                value = OCTET_STRING(value)

            varlist.append( VarBind(OID(oid), value) )

        pdu = SetRequestPDU(
            request_id=self._request_id(),
            vars=VarBindList(*varlist),
        )
        return self._request(host, pdu, community=community or self.rwcommunity)

    def _request(self, host, pdu, community=None):
        end_time = time.time()

        kwargs = {}
        if community is not None:
            kwargs['community'] = community

        request_id = pdu.request_id.value
        message = Message(data=pdu, **kwargs)

        with self._lock:
            self._responses[request_id] = None

        packet = message.serialize()

        response = None
        for i in range(10):
            self._sock.sendto(packet, (host, PORT))
            end_time += 1
            while self._received.wait(end_time - time.time()):
                self._received.clear()

                with self._lock:
                    response = self._responses[request_id]

                if response is not None:
                    pdu = response.data

                    # TODO: return an object that raises an error when you access the value
                    if pdu.error_status:
                        status = pdu.error_status.value
                        index = pdu.error_index.value

                        try:
                            oid = pdu.vars[index-1].name
                        except IndexError:
                            message = "Invalid error index: {}".format(index)
                            raise ProtocolError(message)

                        try:
                            raise STATUS_ERRORS[status](oid.value)
                        except IndexError:
                            message = "Invalid error status: {}".format(status)
                            raise ProtocolError(message)

                    return response.data.vars

        raise Timeout()
