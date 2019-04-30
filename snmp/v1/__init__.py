from binascii import hexlify
from collections import OrderedDict
import logging
import os
import random
import select
import socket
import threading
import time

from ..exceptions import EncodingError, ProtocolError, Timeout
from ..mutex import RWLock
from ..types import *
from .exceptions import TooBig, NoSuchName, BadValue, ReadOnly, GenErr

log = logging.getLogger(__name__)

DUMMY_EVENT = threading.Event()
DUMMY_EVENT.set()

ERRORS = {
    1: TooBig,
    2: NoSuchName,
    3: BadValue,
    4: ReadOnly,
    5: GenErr,
}

PORT = 161
RECV_SIZE = 65507
MAX_REQUEST_ID = 0xffffffff
VERSION = 0

class PendTable:
    def __init__(self):
        self.lock = threading.Lock()

        # The two events signal the arrival of the value for the oid itself,
        # or the variable returned by a GetNext request (respectively)
        # {
        #   <oid>: [<Event>, <Event>],
        #   ...
        # }
        self.oids = {}

        # Used by set() to make sure multiple set requests to the same OID
        # do not overlap in time
        # {
        #   <oid>: <Event>,
        #   ...
        # }
        self.sets = {}

# background thread to process responses
def _listen_thread(sock, pipe, requests, rlock, data, dlock, port=PORT):
    while True:
        # wait for data on sock or pipe
        r, _, _ = select.select([sock, pipe], [], [])

        if pipe in r:
            # exit from this thread
            # don't bother processing any more responses; the calling
            #   application has all the data they need
            break

        # listen for UDP packets from the correct port
        packet, (host, p) = sock.recvfrom(RECV_SIZE)
        if p != PORT:
            continue

        try:
            # convert bytes to Message object
            message = ASN1.deserialize(packet, cls=Message)

            # ignore garbage packets
            if message.version != VERSION:
                continue

            # force a full parse; invalid packet will raise an error
            message.poke()

        except (EncodingError, ProtocolError) as e:
            # this should take care of filtering out invalid traffic
            log.debug("{}: {}: {}".format(
                e.__class__.__name__, e, hexlify(packet).decode()
            ))
            continue

        request_id = message.data.request_id.value
        try:
            with rlock:
                request, event = requests[request_id][:2]
        except KeyError:
            # ignore responses for which there was no request
            msg = "Received unexpected response from {}: {}"
            log.debug(msg.format(host, hexlify(packet).decode()))
            continue

        # while we don't explicitly check every possible protocol violation
        # this one would cause IndexErrors below, which I'd rather avoid
        if len(message.data.vars) != len(request.data.vars):
            msg = "VarBindList length mismatch:\n(Request) {}(Response) {}"
            log.error(msg.format(request, message))
            continue

        requests.pop(request_id)
        next = isinstance(request.data, GetNextRequestPDU)

        error = None
        error_status = message.data.error_status.value
        if error_status != 0:
            log.debug(message.data)
            error_index = message.data.error_index.value
            try:
                cls = ERRORS[error_status]
            except KeyError:
                msg = "Invalid error status: {}"
                error = ProtocolError(msg.format(error_status))
            else:
                try:
                    varbind = message.data.vars[error_index-1]
                except IndexError:
                    msg = "Invalid error index: {}"
                    error = ProtocolError(msg.format(error_index))
                else:
                    error = cls(varbind.name.value)

        with dlock:
            try:
                host_data = data[host]
            except KeyError:
                host_data = {}
                data[host] = host_data

            for i, varbind in enumerate(message.data.vars):
                # won't make a difference if error is None
                varbind.error = error

                requested = request.data.vars[i].name.value
                oid = varbind.name.value

                if next:
                    try:
                        host_data[requested][1] = oid
                    except KeyError:
                        host_data[requested] = [None, oid]
                elif requested != oid:
                    msg = "OID ({}) does not match requested ({})"
                    log.warning(msg.format(oid, requested))

                    # this will cause a ProtocolError to be raised in get()
                    # However, if this data is never accessed, the error
                    # will go unnoticed.
                    # Assuming, however, that the agent is correctly
                    # implemented and the channel is secure, this should
                    # never happen
                    try:
                        host_data[requested][0] = None
                    except KeyError:
                        host_data[requested] = [None, None]

                # update data table
                try:
                    host_data[oid][0] = varbind
                except KeyError:
                    host_data[oid] = [varbind, None]

        msg = "Done processing response from {} (ID={})"
        log.debug(msg.format(host, request_id))

        # alert the main thread that the data is ready
        event.set()

    log.debug("Listener thread exiting")

def _monitor_thread(sock, done, requests, rlock, data, dlock, port=PORT, resend=1):
    delay = 0
    while not done.wait(timeout=delay):
        with rlock:
            try:
                ID = next(iter(requests))
            except StopIteration:
                delay = resend
            else:
                timestamp = requests[ID][3]
                diff = time.time() - timestamp

                if diff >= resend:
                    delay = 0
                    message, event, host, _, count = requests.pop(ID)
                    if count:
                        timestamp += resend
                        requests[ID] = (
                            message, event, host, timestamp, count-1
                        )
                else:
                    delay = 1-diff

        if delay == 0:
            if count:
                msg = "Resending to {} (ID={})"
                log.debug(msg.format(host, message.data.request_id))
                sock.sendto(message.serialize(), (host, PORT))
            else:
                with dlock:
                    msg = "Request to {} timed out (ID={})"
                    log.debug(msg.format(host, message.data.request_id))
                    for varbind in message.data.vars:
                        varbind.error = Timeout(varbind.name.value)
                        oid = varbind.name.value
                        try:
                            host_data = data[host]
                        except KeyError:
                            host_data = {}
                            data[host] = host_data

                        try:
                            _, next_oid = host_data[oid]
                        except KeyError:
                            next_oid = None

                        # causes GETNEXT requests to register the timeout
                        if isinstance(message.data, GetNextRequestPDU):
                            next_oid = oid

                        host_data[oid] = [varbind, next_oid]

                event.set()

    log.debug("Monitor thread exiting")

class SNMPv1:
    def __init__(self, community, rwcommunity=None, port=PORT, resend=1):
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
        self._closed = threading.Event()

        # counting by an odd number will hit every
        # request id once before repeating
        self._count_by = random.randint(0, MAX_REQUEST_ID//2) * 2 + 1
        self._next_id = self._count_by

        # This is an OrderedDict so the monitoring thread can iterate through
        # them in order
        # <timestamp> is the timestamp of the most recent transmission
        # <count> is the number of remaining re-transmits before Timeout
        # {
        #   <request_id>: (<Message>, <Event>, <host>, <timestamp>, <count>),
        #   ...
        # }
        self._requests = OrderedDict()
        self._rlock = threading.Lock()

        # table of pending requests (prevents re-sending packets unnecessarily)
        # {
        #   <host_ip>: <PendTable>,
        #   ...
        # }
        self._pending = {}
        self._plock = threading.Lock()

        # table of responses
        # {
        #   <host_ip>: {
        #       <oid>: [
        #           <VarBind>,
        #           <next_oid>,
        #       ],
        #       ...
        #   },
        #   ...
        # }
        self._data = {}
        self._drlock, self._dwlock = RWLock()

        self._listener = threading.Thread(
            target=_listen_thread,
            args=(
                self._sock,
                self._read_pipe,
                self._requests,
                self._rlock,
                self._data,
                self._dwlock,
            ),
            kwargs={"port":port},
        )
        self._listener.start()

        self._monitor = threading.Thread(
            target=_monitor_thread,
            args=(
                self._sock,
                self._closed,
                self._requests,
                self._rlock,
                self._data,
                self._dwlock,
            ),
            kwargs={
                "port": port,
                "resend": resend,
            },
        )
        self._monitor.start()

    def close(self):

        log.debug("Sending shutdown signal to helper threads")
        self._closed.set()
        self._write_pipe.write('\0')
        self._write_pipe.flush()

        self._listener.join()
        self._monitor.join()
        log.debug("All helper threads done")

        self._read_pipe.close()
        self._write_pipe.close()
        self._sock.close()

        self._read_pipe = None
        self._write_pipe = None
        self._sock = None

    def __del__(self):
        if not self._closed.is_set():
            self.close()

    def _request_id(self):
        request_id = self._next_id
        self._next_id = (request_id + self._count_by) & MAX_REQUEST_ID

        return request_id

    def get(self, host, *oids, community=None, block=True, timeout=10,
                                            refresh=False, next=False):
        # this event will be stored in the pending table under this request ID
        # the _listener_thread will signal when the data is ready
        main_event = threading.Event()

        # store the first error found on a cached VarBind and raise it only
        # after the request has been sent for any other oids there may be
        error = None

        # used for blocking calls to wait for all responses
        events = set()

        # set of oids that are neither in self._data nor self._pending
        send = set()

        # return value (values[i] corresponds to oids[i])
        values = [None] * len(oids)

        with self._plock:
            try:
                host_pending = self._pending[host]
            except KeyError:
                host_pending = PendTable()
                self._pending[host] = host_pending

        with self._drlock:
            try:
                host_data = self._data[host]
            except KeyError:
                host_data = {}

        # acquiring the lock all the way out here should minimize the number of
        # packets sent, even if this object is being shared by multiple threads
        with host_pending.lock:
            for i, oid in enumerate(oids):
                if not refresh:
                    try:
                        event = host_pending.oids[oid][int(next)]
                    except KeyError:
                        pass
                    else:
                        # request has been sent already and is pending
                        if event and not event.is_set():
                            events.add(event)
                            # don't fetch cached value, don't re-send request
                            continue

                    try:
                        # TODO: make a separate lock for each host's data
                        with self._drlock:
                            value, next_oid = host_data[oid]
                            if next:
                                value, _ = host_data[next_oid]
                    except KeyError:
                        pass
                    else:
                        # cached value found
                        if value is not None:
                            # raise any errors after the request is sent
                            error = error or value.error

                            # set return value
                            values[i] = value
                            continue

                # add this item to the pending table
                try:
                    host_pending.oids[oid][int(next)] = main_event
                except KeyError:
                    if next:
                        host_pending.oids[oid] = [None, main_event]
                    else:
                        host_pending.oids[oid] = [main_event, None]

                # make a note to include this OID in the request
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
                version = VERSION,
                data = pdu,
                community = community or self.rocommunity,
            )

            with self._rlock:
                self._requests[request_id] = (
                    message, main_event, host, time.time(), timeout-1
                )

            self._sock.sendto(message.serialize(), (host, self.port))
            log.debug("Sent request to {} (ID={})".format(host, request_id))

        if error is not None:
            raise error

        if not block:
            return values

        # wait for all requested oids to receive a response
        for event in events:
            event.wait()

        # the data table should now be all up to date
        with self._drlock:
            values = []
            try:
                host_data = self._data[host]
            except KeyError:
                # shouldn't get here, ProtocolError will be triggered below
                host_data = {}

            for oid in oids:
                try:
                    value, next_oid = host_data[oid]
                    if next:
                        value, _ = host_data[next_oid]
                except KeyError:
                    value = None

                if value is None:
                    raise ProtocolError("Missing variable: {}".format(oid))
                elif value.error is not None:
                    raise value.error

                values.append(value)

        return values

    def get_next(self, *args, **kwargs):
        kwargs['next'] = True
        return self.get(*args, **kwargs)

    def set(self, host, oid, value, community=None, block=True, timeout=10):
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
            version = VERSION,
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

                    host_pending.oids[oid] = [main_event, next_oid]
                    host_pending.sets[oid] = main_event

        # wait for pending requests to be serviced
        pend_event.wait()

        with self._rlock:
            self._requests[request_id] = (
                message, main_event, host, time.time(), timeout-1
            )

        self._sock.sendto(message.serialize(), (host, self.port))
        msg = "SET request sent to {} (ID={}):\n{}"
        log.debug(msg.format(host, request_id, pdu))

        if not block:
            return

        # no need to duplicate code; just call self.get()
        return self.get(host, oid, block=True)

    def walk(self, host, oid, **kwargs):
        start = oid
        while True:

            var, = self.get_next(host, oid, block=True, **kwargs)
            oid = var.name.value

            if not oid.startswith(start):
                return

            # send now to speed access on the next iteration
            self.get_next(host, oid, block=False, **kwargs)

            yield [var]
