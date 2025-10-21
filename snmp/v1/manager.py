__all__ = ["SNMPv1Manager"]

from snmp.pdu import *

class SNMPv1Manager:
    def __init__(self, admin, channel, community, autowait = True):
        self.autowait = autowait
        self.channel = channel

        self.admin = admin
        self.defaultCommunity = community

    def sendRequest(self,
        request,
        community = None,
        wait = None,
        timeout = 10.0,
        refreshPeriod = 1.0,
    ):
        if community is None:
            community = self.defaultCommunity

        if wait is None:
            wait = self.autowait

        handle = self.admin.openRequest(
            request,
            community,
            self.channel,
            timeout,
            refreshPeriod,
        )

        if wait:
            return handle.wait()
        else:
            return handle

    def get(self, *oids, **kwargs):
        pdu = GetRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getBulk(self, *oids, nonRepeaters=0, maxRepetitions=1, **kwargs):
        # Validate arguments
        _ = GetBulkRequestPDU(
            *oids,
            nonRepeaters=nonRepeaters,
            maxRepetitions=maxRepetitions,
        )

        if maxRepetitions == 0:
            oids = oids[:nonRepeaters]

        pdu = GetNextRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        pdu = SetRequestPDU(*varbinds)
        return self.sendRequest(pdu, **kwargs)
