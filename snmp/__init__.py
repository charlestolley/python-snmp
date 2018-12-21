import random

from .authentication import Trivial
from .communication import UDP
from .exceptions import ProtocolError
from .types import ASN1, GetRequestPDU, GetNextRequestPDU, Message, NULL, OCTET_STRING, OID, SetRequestPDU, VarBind, VarBindList

class Manager:
    # TODO: allow user to specify custom authenticator/communicator
    def __init__(self, community=None, rwcommunity=None):
        self.authenticator = Trivial()
        self.communicator = UDP()

        self.rocommunity = community
        self.rwcommunity = rwcommunity or community

    def _request_id(self):
        # TODO: track request id's to prevent repeats
        return random.randint(0, 0xffffffff)

    def _request_done(self, request_id):
        pass

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

        # effectively a no-op for now
        secured = self.authenticator.secure(pdu)

        message = Message(data=secured, **kwargs)
        self.communicator.send(host, message.serialize())

        # TODO: create a better system to handle responses
        while True:
            packet = self.communicator.recv()
            response = ASN1.deserialize(packet, cls=Message)

            if response.version != 0:
                raise ProtocolError("Version mismatch")

            if response.community != kwargs['community']:
                raise ProtocolError("Bad community")

            self._request_done(response.data.request_id.value)
            return response.data.vars
