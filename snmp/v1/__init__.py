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

RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff

class PendTable:
    def __init__(self):
        self.lock = threading.Lock()

        self.oids = {}
        self.requests = OrderedDict()

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
                message = "Received unexpected response from {}: {}"
                log.warning(message.format(host, hexlify(packet).decode()))
                continue

            with self._dwlock:
                try:
                    host_data = self._data[host]
                except KeyError:
                    host_data = {}
                    self._data[host] = host_data

                for varbind in message.data.vars:
                    # update data table
                    host_data[varbind.name.value] = varbind

            msg = "Done processing response from {} (ID={})"
            log.debug(msg.format(host, request_id))

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

    def get(self, host, *oids, community=None, block=True, refresh=False):
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
                            values[i] = host_data[oid]
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
                        event = host_pending.oids[oid]
                    except KeyError:
                        pass
                    else:
                        # do not re-request oids that are already pending
                        if not event.is_set():
                            # add to events set so we can wait on it later
                            events.add(event)
                            continue

                    # put all oids on one event so they will trigger at once
                    host_pending.oids[oid] = main_event
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
            log.debug("Sent request to {} (ID={})".format(host, request_id))

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

                    # TODO: return an object that raises an error when you
                    #       access the value
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
