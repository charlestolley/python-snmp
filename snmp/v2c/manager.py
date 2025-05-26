__all__ = ["SNMPv2cManager"]

import weakref

from snmp.asn1 import *
from snmp.message import *
from snmp.pdu import *
from snmp.scheduler import *
from snmp.smi import *
from snmp.transport import *
from snmp.typing import *
from snmp.utils import *

class SNMPv2cManager:
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

    def get(self, *oids: Union[str, OID], **kwargs):
        pdu = GetRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getBulk(self,
        *oids: Union[str, OID],
        nonRepeaters: int = 0,
        maxRepetitions: int = 0,
        **kwargs,
    ):
        pdu = GetBulkRequestPDU(
            *oids,
            nonRepeaters=nonRepeaters,
            maxRepetitions=maxRepetitions,
        )

        return self.sendRequest(pdu, **kwargs)

    def getNext(self, *oids: Union[str, OID], **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def set(self,
        *varbinds: Union[
            Tuple[
                Union[str, OID],
                Optional[ASN1],
            ],
            VarBind,
        ],
        **kwargs: Any,
    ):
        vbList = (VarBind(*varbind) for varbind in varbinds)
        pdu = SetRequestPDU(*vbList)
        return self.sendRequest(pdu, **kwargs)
