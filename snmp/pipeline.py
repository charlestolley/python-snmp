__all__ = ["Catcher", "MessageSorter", "VersionDecoder"]

import logging
import random
import weakref

from os import linesep

from snmp.ber import ParseError
from snmp.exception import *
from snmp.message import *
from snmp.security import UnknownSecurityModel
from snmp.utils import *

class Catcher:
    def __init__(self, listener, verbose=False):
        self.listener = listener
        self.logger = logging.getLogger(__name__.split(".")[0])
        self.verbose = verbose

        self.packets = 0
        self.parseErrors = 0
        self.badVersions = 0
        self.invalidMsgs = 0
        self.unknownSecurityModels = 0

    def hear(self, data: bytes, channel) -> None:
        self.packets += 1

        try:
            self.listener.hear(data, channel)
        except ParseError as err:
            self.parseErrors += 1

            if self.verbose:
                self.logger.debug(f"{typename(err)}:{err}{linesep}{err.data}")
        except BadVersion as err:
            self.badVersions += 1

            if self.verbose:
                self.logger.debug(f"{typename(err)}:{err}{linesep}{err.data}")
        except InvalidMessage as err:
            self.invalidMsgs += 1

            if self.verbose:
                self.logger.debug(f"{typename(err)}:{err}{linesep}{err.data}")
        except UnknownSecurityModel as err:
            self.unknownSecurityModels += 1

            if self.verbose:
                self.logger.debug(f"{typename(err)}:{err}{linesep}{err.data}")
        except IncomingMessageError as err:
            if self.verbose:
                self.logger.debug(f"{err!r}\n{data!r}")
        except Exception as exc:
            self.logger.exception(exc)

class VersionDecoder:
    def __init__(self):
        self.listeners = weakref.WeakValueDictionary()

    def hear(self, data, channel):
        msgVersion = VersionOnlyMessage.decodeExact(data).version

        try:
            listener = self.listeners[msgVersion]
        except KeyError as err:
            errmsg = f"Ignoring {msgVersion.name} message" \
                " because no application is listening for it."
            errdata = subbytes(data)
            raise BadVersion(errmsg, errdata) from err
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
            if not pduType.RESPONSE_CLASS:
                self.unknownHandlers += 1
                if pduType.CONFIRMED_CLASS:
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
