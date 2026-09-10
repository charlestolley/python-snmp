__all__ = ["SNMPv2cMessageSorter"]

import weakref

from snmp.message import Message
from snmp.pdu import *

pduTypes = {
    cls.TAG: cls for cls in (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
        GetBulkRequestPDU,
        InformRequestPDU,
        SNMPv2TrapPDU,
        ReportPDU,
    )
}

class SNMPv2cMessageSorter:
    def __init__(self):
        self.subscribers = weakref.WeakValueDictionary()

    def register(self, pduType, subscriber):
        subscribed = self.subscribers.setdefault(pduType.TAG, subscriber)
        return subscriber is subscribed

    def hear(self, data, channel):
        message = Message.decodeExact(data, types=pduTypes)

        try:
            subscriber = self.subscribers[message.pdu.TAG]
        except KeyError:
            pass
        else:
            subscriber.hear(message, channel)
