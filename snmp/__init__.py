import logging
import os
import random
import select
import socket
import threading
import time

from .exceptions import EncodingError, ProtocolError, Timeout, STATUS_ERRORS
from .mutex import RWLock
from .types import *

log = logging.getLogger(__name__)

PORT = 161
RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff

class Manager:
    VERSION = 0
    def __init__(self, community=None, rwcommunity=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._sock.bind(('', 0))

        r, w = os.pipe()
        self._read_pipe = os.fdopen(r)
        self._write_pipe = os.fdopen(w, 'w')

        self.rocommunity = community
        self.rwcommunity = rwcommunity or community

        # counting by an odd number should hit every request id once before repeating
        self._count_by = random.randint(0, MAX_REQUEST_ID//2) * 2 + 1
        self._next_id = self._count_by

        self._data = {}
        self._data['rlock'], self._data['wlock'] = RWLock()
        self._received = threading.Event()

        self._listener = threading.Thread(target=self._listen)
        self._listener.start()

    def _listen(self):
        while True:
            r, _, _ = select.select([self._sock, self._read_pipe], [], [])
            if self._read_pipe in r:
                break

            packet, (host, port) = self._sock.recvfrom(RECV_SIZE)
            if port != PORT:
                continue

            try:
                message = ASN1.deserialize(packet, cls=Message)

                if message.version != self.VERSION:
                    continue

                message.poke()

            except (EncodingError, ProtocolError) as e:
                continue

            with self._data['wlock']:
                self._data[message.data.request_id.value] = message

            self._received.set()

    def close(self):
        log.debug("Sending shutdown signal to listener thread")
        self._write_pipe.write('\0')
        self._write_pipe.flush()

        log.debug("Joining self._listener")
        self._listener.join()
        self._listener = None

        self._read_pipe.close()
        self._write_pipe.close()
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
        message = Message(version=self.VERSION, data=pdu, **kwargs)

        with self._data['rlock']:
            self._data[request_id] = None

        packet = message.serialize()

        response = None
        for i in range(10):
            self._sock.sendto(packet, (host, PORT))
            end_time += 1
            while self._received.wait(end_time - time.time()):
                self._received.clear()

                with self._data['rlock']:
                    response = self._data[request_id]

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
