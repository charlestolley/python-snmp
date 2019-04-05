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

        # used to shut down background threads
        r, w = os.pipe()
        self._read_pipe = os.fdopen(r)
        self._write_pipe = os.fdopen(w, 'w')

        # counting by an odd number will hit every
        # request id once before repeating
        self._count_by = random.randint(0, MAX_REQUEST_ID//2) * 2 + 1
        self._next_id = self._count_by

        # TODO: expire out of pend table if response does not arrive
        # table of pending requests (prevents re-sending packets unnecessarily)
        # {
        #   <host_ip>: {
        #       <oid>: threading.Event,
        #       ...
        #   },
        #   ...
        # }
        self._pending = {}
        self._plock = threading.Lock()

        # table of responses
        # {
        #   <host_ip>: {
        #       <oid>: VarBind,
        #       ...
        #   },
        #   ...
        # }
        self._data = {}
        self._drlock, self._dwlock = RWLock()

        self._listener = threading.Thread(target=self._listen_thread)
        self._listener.start()

    # background thread to process responses
    def _listen_thread(self):
        while True:
            # wait for data on self._sock or self._read_pipe
            r, _, _ = select.select([self._sock, self._read_pipe], [], [])

            if self._read_pipe in r:
                # exit from this thread
                # don't bother processing any more responses; the calling
                #   application has all the data they need
                break

            # listen for UDP packets from the correct port
            packet, (host, port) = self._sock.recvfrom(RECV_SIZE)
            if port != self.port:
                continue

            try:
                # convert bytes to Message object
                message = ASN1.deserialize(packet, cls=Message)

                # ignore garbage packets
                if message.version != self.VERSION:
                    continue

                # force a full parse; invalid packet will raise EncodingError
                message.poke()

            except (EncodingError, ProtocolError) as e:
                log.exception(e)
                continue

            log.debug("Response from {}".format(host))

            # TODO: error handling
            with self._dwlock:
                # collects threading.Event objects from pending table
                events = set()

                try:
                    host_data = self._data[host]
                except KeyError:
                    host_data = {}
                    self._data[host] = host_data

                for varbind in message.data.vars:
                    oid = varbind.name.value
                    value = varbind.value

                    with self._plock:
                        # TODO: find out if the 'host' might be different
                        #       from the IP to which the request was sent
                        events.add(self._pending[host][oid])

                    # update data table
                    host_data[oid] = varbind

                # use the lock around this to avoid race condition with get()
                with self._plock:
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

    def get(self, host, *oids, community=None, block=True, refresh=False):
        # used for blocking calls to wait for all responses
        events = set()

        # we can use a single event for all entries in the pending table
        # as long as we don't ever try to re-use it with clear() later
        main_event = threading.Event()

        # set of oids for which we have no value (or value is expired)
        missing = set()

        # set of missing oids that are not in the pending table
        send = set()

        # values[i] corresponds to oids[i]
        values = [None] * len(oids)

        with self._drlock:
            if refresh:
                missing = set(oids)
            else:
                try:
                    host_data = self._data[host]
                except KeyError:
                    missing = set(oids)
                else:

                    for i, oid in enumerate(oids):
                        try:
                            # use cached value
                            values[i] = host_data[oid]
                        except KeyError:
                            # value not found or expired
                            missing.add(oid)

            # don't release self._drlock yet because the listener might remove
            # stuff from the pending table, which would cause us to send extra
            # requests for no reason

            if missing:
                with self._plock:
                    try:
                        host_pending = self._pending[host]
                    except KeyError:
                        host_pending = {}
                        self._pending[host] = host_pending

                    # check if requests already exist for the missing oids
                    for oid in missing:
                        try:
                            event = host_pending[oid]
                        except KeyError:
                            pass
                        else:
                            # an event that is set is presumed to be outdated
                            if not event.is_set():
                                events.add(event)
                                continue

                        # put all oids on one event so they will trigger at once
                        host_pending[oid] = main_event
                        send.add(oid)

        # send any requests that are not found to be pending
        if send:
            events.add(main_event)
            pdu = GetRequestPDU(
                request_id=self._request_id(),
                vars=VarBindList(
                    *[VarBind(OID(oid), NULL()) for oid in send]
                ),
            )

            message = Message(
                version = self.VERSION,
                data = pdu,
                community = community or self.rocommunity,
            )

            self._sock.sendto(message.serialize(), (host, self.port))
            log.debug("Sent request to {}".format(host))

        if not block:
            return values

        # wait for all requested oids to receive a response
        for event in events:
            # TODO: trigger the event in the case of a timeout
            event.wait()

        # the data table should now be all up to date
        with self._drlock:
            values = []
            try:
                host_data = self._data[host]
            except KeyError:
                host_data = {}

            for oid in oids:
                try:
                    value = host_data[oid]
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
