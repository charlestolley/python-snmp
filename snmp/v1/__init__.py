import logging
import os
import random
import select
import socket
import threading
import time

from ..exceptions import EncodingError, ProtocolError, Timeout, STATUS_ERRORS
from ..mutex import RWLock
from ..types import *

log = logging.getLogger(__name__)

RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff

class SNMPv1:
    VERSION = 0
    def __init__(self, community=None, rwcommunity=None, port=161):
        self.rocommunity = community
        self.rwcommunity = rwcommunity or community
        self.port = port

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._sock.bind(('', 0))

        r, w = os.pipe()
        self._read_pipe = os.fdopen(r)
        self._write_pipe = os.fdopen(w, 'w')

        # counting by an odd number will hit every
        # request id once before repeating
        self._count_by = random.randint(0, MAX_REQUEST_ID//2) * 2 + 1
        self._next_id = self._count_by

        self._pending = {}
        self._prlock, self._pwlock = RWLock()

        self._data = {}
        self._drlock, self._dwlock = RWLock()
        self._received = threading.Event()

        self._listener = threading.Thread(target=self._listen_thread)
        self._listener.start()

    def _listen_thread(self):
        while True:
            r, _, _ = select.select([self._sock, self._read_pipe], [], [])
            if self._read_pipe in r:
                break

            packet, (host, port) = self._sock.recvfrom(RECV_SIZE)
            if port != self.port:
                continue

            try:
                message = ASN1.deserialize(packet, cls=Message)

                if message.version != self.VERSION:
                    continue

                message.poke()

            except (EncodingError, ProtocolError) as e:
                log.exception(e)
                continue

            # TODO: error handling
            with self._dwlock:
                try:
                    host_data = self._data[host]
                except KeyError:
                    host_data = {}
                    self._data[host] = host_data

                now = time.time()
                events = set()
                for varbind in message.data.vars:
                    oid = varbind.name.value
                    value = varbind.value

                    try:
                        timestamp = host_data[oid][1]
                    except KeyError:
                        timestamp = 0

                    if now > timestamp:
                        with self._prlock:
                            # TODO: the trouble is that host might be different
                            #       from the IP to which the request was sent
                            events.add(self._pending[host][oid])

                        host_data[oid] = (varbind, now)

                with self._pwlock:
                    for event in events:
                        event.set()

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

    def get(self, host, *oids, community=None, block=True, cached=1):
        events = set()
        main_event = threading.Event()
        missing = []
        send = []
        really_send = set()
        values = [None] * len(oids)

        with self._drlock:
            try:
                host_data = self._data[host]
            except KeyError:
                missing = oids
            else:

                now = time.time()

                for i, oid in enumerate(oids):
                    try:
                        value, timestamp = host_data[oid]
                    except KeyError:
                        value, timestamp = (None, 0)

                    if timestamp + cached < now:
                        missing.append(oid)
                    else:
                        values[i] = value

            if missing:
                with self._prlock:
                    try:
                        host_pending = self._pending[host]
                    except KeyError:
                        send = missing
                    else:
                        for oid in missing:
                            try:
                                event = host_pending[oid]
                            except KeyError:
                                pass
                            else:
                                if not event.is_set():
                                    events.add(event)
                                    continue

                            send.append(oid)

            if send:
                with self._pwlock:
                    try:
                        host_pending = self._pending[host]
                    except KeyError:
                        host_pending = {}
                        self._pending[host] = host_pending

                    for oid in send:
                        try:
                            event = host_pending[oid]
                        except KeyError:
                            pass
                        else:
                            if not event.is_set():
                                events.add(event)
                                continue

                        # put all oids on one event so they will trigger at once
                        host_pending[oid] = main_event
                        really_send.add(oid)

            if really_send:
                events.add(main_event)
                pdu = GetRequestPDU(
                    request_id=self._request_id(),
                    vars=VarBindList(
                        *[VarBind(OID(oid), NULL()) for oid in really_send]
                    ),
                )
                message = Message(
                    version = self.VERSION,
                    data = pdu,
                    community = community or self.rocommunity,
                )
                self._sock.sendto(message.serialize(), (host, self.port))

        if not block:
            return values

        for event in events:
            event.wait()

        with self._drlock:
            values = []
            try:
                host_data = self._data[host]
            except KeyError:
                host_data = {}

            for oid in oids:
                try:
                    value = host_data[oid][0]
                except KeyError:
                    # TODO: replace with something that throws a
                    #       a protocol error
                    value = None

                values.append(value)

        return values

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

        with self._drlock:
            self._data[request_id] = None

        packet = message.serialize()

        response = None
        for i in range(10):
            self._sock.sendto(packet, (host, self.port))
            end_time += 1
            while self._received.wait(end_time - time.time()):
                self._received.clear()

                with self._drlock:
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
