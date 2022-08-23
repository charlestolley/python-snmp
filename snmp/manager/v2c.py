import heapq
import threading

from snmp.dispatcher import *
from snmp.message import *
from snmp.pdu.v2 import *
from . import *

class Request(Dispatcher.Handle):
    def __init__(self, pdu, manager, community):
        self.community = community
        self.manager = manager
        self.pdu = pdu

        self.callback = None
        self.messages = set()

        self.event = threading.Event()
        self.expired = False
        self.fulfilled = False
        self.response = None

    def __del__(self):
        if self.callback is not None:
            self.close()

    def close(self):
        for message in self.messages:
            self.callback(message)

        self.callback = None
        self.messages.clear()

    def addCallback(self, callback, msgID):
        if self.callback is None:
            self.callback = callback

        assert self.callback == callback
        self.messages.add(msgID)

    def push(self, response):
        self.response = response
        self.event.set()

    def send(self):
        pdu = self.pdu
        community = self.community
        return self.manager.sendPdu(pdu, self, community)

    def wait(self):
        pdu = None
        while not self.expired:
            timeout = self.manager.refresh()
            if self.event.wait(timeout=timeout):
                pdu = self.response.pdu
                self.fulfilled = True
                break

        self.close()
        if pdu is None:
            raise Timeout()
        else:
            return pdu

class SNMPv2cManager:
    def __init__(self, engine, locator, community, autowait=True):
        self.autowait = autowait
        self.locator = locator

        self.localEngine = engine
        self.defaultCommunity = community

        self.lock = threading.Lock()
        self.requests = []

    def refresh(self):
        while True:
            with self.lock:
                entry = self.requests[0]
                result = entry.refresh()

                while result is None:
                    heapq.heappop(self.requests)
                    entry = self.requests[0]
                    result = entry.refresh()

                if result < 0:
                    heapq.heapreplace(self.requests, entry)
                else:
                    return result

    def sendPdu(self, pdu, handle, community):
        return self.localEngine.dispatcher.sendPdu(
            self.locator.domain,
            self.locator.address,
            MessageProcessingModel.SNMPv2c,
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
            heapq.heappush(self.requests, Repeater(request))
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
