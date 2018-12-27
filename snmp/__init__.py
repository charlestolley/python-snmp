import random
import socket

from .exceptions import ProtocolError, STATUS_ERRORS
from .types import ASN1, GetRequestPDU, GetNextRequestPDU, Message, NULL, OCTET_STRING, OID, SetRequestPDU, VarBind, VarBindList

PORT = 161
RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff

class Manager:
    def __init__(self, community=None, rwcommunity=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', 0))

        self.rocommunity = community
        self.rwcommunity = rwcommunity or community

        # counting by an odd number should hit every request id once before repeating
        self._count_by = random.randint(0, MAX_REQUEST_ID//2) * 2 + 1
        self._next_id = self._count_by

    def _request_id(self):
        request_id = self._next_id
        self._next_id = (request_id + self._count_by) & MAX_REQUEST_ID

        return request_id

    def get(self, host, *oids, community=None):
        pdu = GetRequestPDU(
            request_id=self._request_id(),
            vars=VarBindList(*[VarBind(OID(oid), NULL()) for oid in oids]),
        )
        return self.request(host, pdu, community=community or self.rocommunity)

    def get_next(self, host, *oids, community=None):
        pdu = GetNextRequestPDU(
            request_id=self._request_id(),
            vars=VarBindList(*[VarBind(OID(oid), NULL()) for oid in oids]),
        )
        return self.request(host, pdu, community=community or self.rocommunity)

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
        return self.request(host, pdu, community=community or self.rwcommunity)

    def request(self, host, pdu, community=None):
        kwargs = {}
        if community is not None:
            kwargs['community'] = community

        message = Message(data=pdu, **kwargs)
        self.socket.sendto(message.serialize(), (host, PORT))

        # TODO: create a better system to handle responses
        while True:
            packet, (host, port) = self.socket.recvfrom(RECV_SIZE)
            if port != PORT:
                continue

            response = ASN1.deserialize(packet, cls=Message)
            if response.version != 0:
                continue

            response_pdu = response.data
            if response_pdu.error_status:
                status = response_pdu.error_status.value
                index = response_pdu.error_index.value - 1
                oid = response_pdu.vars[index].name

                raise STATUS_ERRORS[status](oid.value)

            return response.data.vars
