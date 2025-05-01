__all__ = ["MessageSorter", "VersionDecoder"]

import weakref
from snmp.message import *

class VersionDecoder:
    def __init__(self):
        self.listeners = weakref.WeakValueDictionary()

    def hear(self, data, channel):
        msgVersion = VersionOnlyMessage.decodeExact(data).version

        try:
            listener = self.listeners[msgVersion]
        except KeyError as err:
            raise BadVersion() from err
        else:
            listener.hear(data, channel)

    def register(self, version, listener):
        registered = self.listeners.setdefault(version, listener)
        return registered is listener

class MessageSorter:
    def __init__(self, interpreter):
        self.interpreter = interpreter
        self.subscribers = weakref.WeakValueDictionary()

        self.unknownHandlers = 0

    def register(self, pduType, subscriber):
        subscribed = self.subscribers.setdefault(pduType.TAG, subscriber)
        return subscriber is subscribed

    def forward(self, message, channel):
        pduType = self.interpreter.pduType(message)

        try:
            subscriber = self.subscribers[pduType.TAG]
        except KeyError:
            if not issubclass(pduType, Response):
                self.unknownHandlers += 1
                if issubclass(pduType, Confirmed):
                    reportMessage = self.interpreter.makeReport(
                        message,
                        VarBind(
                            snmpUnknownPDUHandlersInstance,
                            Counter32(self.unknownHandlers),
                        )
                    )

                    if reportMessage is not None:
                        try:
                            data = self.interpreter.encode(reportMessage)
                            channel.send(data)
                        except Exception:
                            pass
        else:
            subscriber.hear(message, channel)

    def hear(self, data, channel):
        try:
            message = self.interpreter.decode(data)
        except ReportMessage as report:
            self.send(report.message, channel)
        else:
            self.forward(message, channel)

    def send(self, message, channel):
        channel.send(self.interpreter.encode(message))
