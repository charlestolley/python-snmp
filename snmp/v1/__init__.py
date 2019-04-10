from binascii import hexlify
from collections import OrderedDict
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

DUMMY_EVENT = threading.Event()
DUMMY_EVENT.set()

RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff

class PendTable:
    def __init__(self):
        self.lock = threading.Lock()

        self.oids = {}
        self.requests = OrderedDict()
        self.sets = {}

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

        self.start = time.time()

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
                # not sure if it's necessary to acquire the lock, but whatever
                with self._plock:
                    host_pending = self._pending[host]
            except KeyError:
                # ignore unknown traffic
                message = "Received unsolicited packet from {}: {}"
                log.warning(message.format(host, hexlify(packet).decode()))
                continue

            try:
                # convert bytes to Message object
                message = ASN1.deserialize(packet, cls=Message)

                # ignore garbage packets
                if message.version != self.VERSION:
                    continue

                # force a full parse; invalid packet will raise an error
                message.poke()

            except (EncodingError, ProtocolError) as e:
                # this should take care of filtering out invalid traffic
                log.warning("{}: {}: {}".format(
                    e.__class__.__name__, e, hexlify(packet).decode()
                ))
                continue

            request_id = message.data.request_id.value
            try:
                with host_pending.lock:
                    # TODO: check that request matches response 
                    request, event = host_pending.requests.pop(request_id)
            except KeyError:
                # ignore responses for which there was no request
                msg = "Received unexpected response from {}: {}"
                log.warning(msg.format(host, hexlify(packet).decode()))
                continue

            if len(message.data.vars) != len(request.data.vars):
                msg = "VarBindList length mismatch:\n(Request) {}(Response) {}"
                log.error(msg.format(request, message))
                continue

            next = isinstance(request.data, GetNextRequestPDU)

            # TODO: handle responses with errors
            with self._dwlock:
                try:
                    host_data = self._data[host]
                except KeyError:
                    host_data = {}
                    self._data[host] = host_data

                for i, varbind in enumerate(message.data.vars):
                    oid = varbind.name.value
                    # update data table
                    try:
                        host_data[oid][0] = varbind
                    except KeyError:
                        host_data[oid] = [varbind, None]

                    if next:
                        prev = request.data.vars[i].name.value
                        try:
                            host_data[prev][1] = oid
                        except KeyError:
                            host_data[prev] = [None, oid]

            msg = "Done processing response from {} (ID={}) @ {}"
            log.debug(msg.format(host, request_id, time.time()-self.start))

            # alert the main thread that the data is ready
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

    def get(self, host, *oids, community=None, block=True,
                                refresh=False, next=False):
        # this event will be stored in the pending table under this request ID
        # the _listener_thread will signal when the data is ready
        main_event = threading.Event()

        # used for blocking calls to wait for all responses
        events = set()

        # set of oids for which there is currently no data
        missing = set()

        # set of missing oids that are also not in the pending table
        send = set()

        # return value (values[i] corresponds to oids[i])
        values = [None] * len(oids)

        with self._drlock:
            if refresh:
                # ignore any value already in the data table
                missing = set(oids)
            else:
                try:
                    host_data = self._data[host]
                except KeyError:
                    # the data table does not have anything for this host
                    missing = set(oids)
                else:

                    for i, oid in enumerate(oids):
                        try:
                            # use cached value
                            value, next_oid = host_data[oid]
                            if next:
                                # this will raise KeyError if next_oid is None
                                value, _ = host_data[next_oid]

                            if value is None:
                                raise KeyError()

                            values[i] = value
                        except KeyError:
                            # value not found
                            missing.add(oid)

        if missing:
            with self._plock:
                try:
                    host_pending = self._pending[host]
                except KeyError:
                    host_pending = PendTable()
                    self._pending[host] = host_pending

            # check if requests already exist for the missing oids
            for oid in missing:
                with host_pending.lock:
                    try:
                        event = host_pending.oids[oid][int(next)]
                    except KeyError:
                        pass
                    else:
                        # do not re-request oids that are already pending
                        if event and not event.is_set():
                            # add to events set so we can wait on it later
                            events.add(event)
                            continue

                    # put all oids on one event so they will trigger at once
                    try:
                        host_pending.oids[oid][int(next)] = main_event
                    except:
                        host_pending.oids[oid] = (
                            [None, main_event] if next else [main_event, None]
                        )

                    send.add(oid)

        # send any requests that are not found to be pending
        if send:
            events.add(main_event)
            pdu_type = GetNextRequestPDU if next else GetRequestPDU
            pdu = pdu_type(
                request_id=self._request_id(),
                vars=VarBindList(
                    *[VarBind(OID(oid), NULL()) for oid in send]
                ),
            )

            # assign request_id variable this way rather than directly from
            # self._request_id() because self._request_id() returns unsigned
            # values, whereas this method returns signed values, and the key
            # here has to match what is used in the _listener_thread()
            request_id = pdu.request_id.value

            message = Message(
                version = self.VERSION,
                data = pdu,
                community = community or self.rocommunity,
            )

            with host_pending.lock:
                host_pending.requests[request_id] = message, main_event

            self._sock.sendto(message.serialize(), (host, self.port))
            msg = "Sent request to {} (ID={}) @ {}"
            log.debug(msg.format(host, request_id, time.time()-self.start))

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
                    value, next_oid = host_data[oid]
                    if next:
                        value, _ = host_data[next_oid]
                except KeyError:
                    # TODO: replace with something that throws a
                    #       a protocol error
                    value = None

                values.append(value)

        return values

    def get_next(self, *args, **kwargs):
        kwargs['next'] = True
        return self.get(*args, **kwargs)

    def set(self, host, oid, value, community=None, block=True):
        # wrap the value in an ASN1 type
        if isinstance(value, int):
            value = INTEGER(value)
        elif value is None:
            value = NULL()
        elif isinstance(value, ASN1):
            pass
        else:
            if isinstance(value, str):
                value = value.encode()
            value = OCTET_STRING(value)

        # create PDU
        pdu = SetRequestPDU(
            request_id=self._request_id(),
            vars=VarBindList(VarBind(OID(oid), value)),
        )

        request_id = pdu.request_id.value
        message = Message(
            version = self.VERSION,
            data = pdu,
            community = community or self.rwcommunity,
        )

        # get PendTable for this host
        with self._plock:
            try:
                host_pending = self._pending[host]
            except KeyError:
                host_pending = PendTable()
                self._pending[host] = host_pending

        # used to wait for the previous set request to complete
        event = DUMMY_EVENT

        # signaled when _listen_thread processes the response
        main_event = threading.Event()

        # wait for any pending requests to complete before sending
        pend_event = None

        # only allow one outstanding set request at a time
        while pend_event is None:
            # loop until we can put main_event in host_pending.oids
            event.wait()
            with host_pending.lock:
                try:
                    event = host_pending.sets[oid]
                except KeyError:
                    event = DUMMY_EVENT

                # event will not be set if another thread's set request
                # acquires the lock first and stores its main_event to .sets
                if event.is_set():
                    try:
                        pend_event, next_oid = host_pending.oids[oid]
                    except KeyError:
                        pend_event, next_oid = DUMMY_EVENT, None

                    host_pending.oids[oid] = main_event, next_oid
                    host_pending.sets[oid] = main_event

        # wait for pending requests to be serviced
        pend_event.wait()

        with host_pending.lock:
            host_pending.requests[request_id] = message, main_event

        self._sock.sendto(message.serialize(), (host, self.port))
        msg = "Set request to {} (ID={}) @ {}\n:{}"
        log.debug(msg.format(host, request_id, time.time()-self.start, pdu))

        if not block:
            return

        # no need to duplicate code; just call self.get()
        return self.get(host, oid, community=community, block=True)[0]
