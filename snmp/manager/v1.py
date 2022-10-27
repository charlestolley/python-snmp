__all__ = ["SNMPv1Manager"]

import heapq
import math
import threading
import time

from snmp.message import *
from snmp.pdu import *
from snmp.utils import *
from . import *

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
        self.nextRefresh = float("inf")
        self.period = refreshPeriod

    def __del__(self):
        if self.callback is not None:
            self.close()

    def __lt__(self, other):
        a = min(self .expiration, self .nextRefresh)
        b = min(other.expiration, other.nextRefresh)
        return a < b

    @property
    def expired(self):
        return self.expiration <= time.time()

    @property
    def fulfilled(self):
        return self.event.is_set()

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

    def reallySend(self):
        self.manager.sendPdu(self.pdu, self, self.community)

    def refresh(self):
        if self.fulfilled:
            return None

        now = time.time()
        expireTime = self.expiration - now
        if expireTime <= 0.0:
            return None

        refreshTime = self.nextRefresh - now
        delta = min(expireTime, refreshTime)

        if delta < 0.0:
            self.nextRefresh += math.ceil(-delta / self.period) * self.period
            self.reallySend()
            return 0.0
        else:
            return delta

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
            return pdu

class SNMPv1Manager:
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
            MessageProcessingModel.SNMPv1,
            pdu,
            handle,
            community
        )

    def sendRequest(self, pdu, community=None, wait=None, **kwargs):
        if community is None:
            community = self.defaultCommunity

        if wait is None:
            wait = self.autowait

        request = Request(pdu, self, community, **kwargs)

        with self.lock:
            heapq.heappush(self.requests, ComparableWeakReference(request))
            request.send()

        if wait:
            return request.wait()
        else:
            return request

    def get(self, *oids, **kwargs):
        pdu = GetRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        varbinds = (VarBind(*varbind) for varbind in varbinds)
        pdu = SetRequestPDU(*varbinds)
        return self.sendRequest(pdu, **kwargs)
