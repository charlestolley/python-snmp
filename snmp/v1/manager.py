__all__ = ["SNMPv1Manager"]

import weakref

from snmp.asn1 import *
from snmp.manager import *
from snmp.message import *
from snmp.pdu import *
from snmp.scheduler import *
from snmp.smi import *
from snmp.transport import *
from snmp.typing import *
from snmp.utils import *

class Request:
    def __init__(self, scheduler, request):
        self.scheduler = scheduler
        self.callbacks = []

        self.request = request
        self.response = None

        self._expired = False

    def __del__(self):
        if self.active:
            self.close()

    @property
    def active(self):
        return self.response is None and not self.expired

    @property
    def expired(self):
        return self._expired

    @expired.setter
    def expired(self, expired):
        if expired and not self._expired:
            self._expired = True
            self.close()

    def close(self):
        while self.callbacks:
            callback, requestID = self.callbacks.pop()
            callback(requestID)

    def addCallback(self, callback, requestID):
        if self.active:
            self.callbacks.append((callback, requestID))
        else:
            callback(requestID)

    def push(self, message):
        if self.response is None:
            self.response = message.pdu
            self.close()

    def wait(self):
        while self.active:
            self.scheduler.wait()

        if self.response is not None:
            if self.response.errorStatus:
                raise ErrorResponse(
                    self.response.errorStatus,
                    self.response.errorIndex,
                    self.request,
                )
            else:
                return self.response.variableBindings
        else:
            raise Timeout()

class SNMPv1Manager:
    class ExpireTask(SchedulerTask):
        def __init__(self, handle_ref):
            self.handle_ref = handle_ref

        def run(self):
            handle = self.handle_ref()
            if handle is not None:
                handle.expired = True

    class SendTask(SchedulerTask):
        def __init__(self, handle_ref, manager, community):
            self.handle_ref = handle_ref
            self.manager = manager
            self.community = community

        def run(self):
            handle = self.handle_ref()
            if handle is not None and handle.active:
                self.manager.sendPdu(handle.request, handle, self.community)
                return self

    def __init__(self, scheduler, dispatcher, channel, community, autowait = True):
        self.autowait = autowait
        self.channel = channel

        self.dispatcher = dispatcher
        self.defaultCommunity = community
        self.scheduler = scheduler

    def sendPdu(self,
        pdu: PDU,
        handle: Request,
        community: bytes,
    ) -> None:
        self.dispatcher.sendPdu(
            self.channel,
            ProtocolVersion.SNMPv1,
            pdu,
            handle,
            community,
        )

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

        handle = Request(self.scheduler, request)
        reference = weakref.ref(handle)
        expireTask = self.ExpireTask(reference)
        self.scheduler.schedule(expireTask, timeout)

        sendTask = self.SendTask(reference, self, community)
        self.scheduler.schedule(sendTask, period=refreshPeriod)

        if wait:
            return handle.wait()
        else:
            return handle

    def get(self,
        *oids: Union[str, OID],
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
        pdu = GetRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getNext(self,
        *oids: Union[str, OID],
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
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
    ) -> Union[Request, VarBindList]:
        vbList = (VarBind(*varbind) for varbind in varbinds)
        pdu = SetRequestPDU(*vbList)
        return self.sendRequest(pdu, **kwargs)
