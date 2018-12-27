import random
import socket
import threading
import time

from .exceptions import ProtocolError, Timeout, STATUS_ERRORS
from .types import ASN1, GetRequestPDU, GetNextRequestPDU, Message, NULL, OCTET_STRING, OID, SetRequestPDU, VarBind, VarBindList

PORT = 161
RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff

def _listener(sock, data, lock, signal):
    while True:
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

        lock.acquire()
        data[message.data.request_id.value] = message
        signal.set()
        lock.release()

class Manager:
    def __init__(self, community=None, rwcommunity=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', 0))

        self.rocommunity = community
        self.rwcommunity = rwcommunity or community

        # counting by an odd number should hit every request id once before repeating
        self._count_by = random.randint(0, MAX_REQUEST_ID//2) * 2 + 1
        self._next_id = self._count_by

        self.responses = {}
        self.lock = threading.Lock()
        self.received = threading.Event()

        threading.Thread(
            target=_listener,
            args=(self.socket, self.responses, self.lock, self.received),
            daemon=True
        ).start()

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

        self.lock.acquire()
        self.responses[request_id] = None
        self.lock.release()

        packet = message.serialize()

        response = None
        for i in range(10):
            self.socket.sendto(packet, (host, PORT))
            end_time += 1
            while self.received.wait(end_time - time.time()):
                self.lock.acquire()
                self.received.clear()
                response = self.responses[request_id]
                self.lock.release()

                if response is not None:
                    pdu = response.data
                    if pdu.error_status:
                        status = pdu.error_status.value
                        index = pdu.error_index.value - 1
                        oid = pdu.vars[index].name

                        raise STATUS_ERRORS[status](oid.value)

                    return response.data.vars

        raise Timeout()
