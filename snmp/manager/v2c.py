__all__ = ["SNMPv2cManager"]

import heapq
import math
import threading
import time

from snmp.manager import *
from snmp.message import *
from snmp.pdu import *
from snmp.utils import *

class Request(RequestHandle):
    def __init__(self, pdu, manager, community,
                timeout=10.0, refreshPeriod=1.0):
        now = time.time()

        self.community = community
        self.manager = manager
        self.pdu = pdu

        self.callback = None
        self.event = threading.Event()
        self.response = None

        self.expiration = now + timeout
        self._nextRefresh = self.expiration
        self.period = refreshPeriod

    def __del__(self):
        if self.callback is not None:
            self.close()

    @property
    def expired(self):
        return self.expiration <= time.time()

    @property
    def nextRefresh(self):
        return self._nextRefresh

    @nextRefresh.setter
    def nextRefresh(self, value):
        self._nextRefresh = min(self.expiration, value)

    def close(self):
        self.callback(self.pdu.requestID)
        self.callback = None

    def addCallback(self, callback, requestID):
        assert requestID == self.pdu.requestID
        assert self.callback is None

        self.callback = callback

    def push(self, response):
        self.response = response
        self.event.set()

    # Always update self.nextRefresh right before calling this method
    def reallySend(self):
        self.manager.sendPdu(self.pdu, self, self.community)

    def refresh(self):
        if self.event.is_set():
            return None

        now = time.time()
        timeToNextRefresh = self.nextRefresh - now

        if timeToNextRefresh <= 0.0:
            if self.expiration <= now:
                return None

            # Calculating it like this mitigates over-delay
            periodsElapsed = math.ceil(-timeToNextRefresh / self.period)
            self.nextRefresh += periodsElapsed * self.period
            self.reallySend()
            return 0.0
        else:
            return timeToNextRefresh

    def send(self):
        now = time.time()
        self.nextRefresh = now + self.period
        self.reallySend()

    def wait(self):
        pdu = None
        while not self.expired:
            timeout = self.manager.refresh()
            if self.event.wait(timeout=timeout):
                pdu = self.response.pdu
                break

        self.close()
        if pdu is None:
            raise Timeout()
        else:
            if pdu.errorStatus:
                raise ErrorResponse(pdu.errorStatus, pdu.errorIndex, self.pdu)
            else:
                return pdu

class SNMPv2cManager:
    def __init__(self, dispatcher, locator, community, autowait=True):
        self.autowait = autowait
        self.locator = locator

        self.dispatcher = dispatcher
        self.defaultCommunity = community

        self.lock = threading.Lock()
        self.requests = []

    def refresh(self):
        while self.requests:
            with self.lock:
                reference = self.requests[0]
                request = reference()

                if request is None:
                    wait = None
                else:
                    wait = request.refresh()

                if wait is None:
                    heapq.heappop(self.requests)
                    continue
                elif wait > 0.0:
                    return wait
                else:
                    heapq.heapreplace(self.requests, reference)

        return None

    def sendPdu(self, pdu, handle, community):
        self.dispatcher.sendPdu(
            self.locator,
            MessageProcessingModel.SNMPv2c,
            pdu,
            handle,
            community,
        )

    def sendRequest(self, pdu, community=None, wait=None, **kwargs):
        if community is None:
            community = self.defaultCommunity

        if wait is None:
            wait = self.autowait

        request = Request(pdu, self, community, **kwargs)
        reference = ComparableWeakRef(request, key=lambda r: r.nextRefresh)

        with self.lock:
            heapq.heappush(self.requests, reference)
            request.send()

        if wait:
            return request.wait()
        else:
            return request

    def get(self, *oids, **kwargs):
        pdu = GetRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getBulk(self, *oids, nonRepeaters=0, maxRepetitions=0, **kwargs):
        pdu = GetBulkRequestPDU(
            *oids,
            nonRepeaters=nonRepeaters,
            maxRepetitions=maxRepetitions,
        )

        return self.sendRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        varbinds = (VarBind(*varbind) for varbind in varbinds)
        pdu = SetRequestPDU(*varbinds)
        return self.sendRequest(pdu, **kwargs)
