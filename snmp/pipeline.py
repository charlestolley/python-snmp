__all__ = ["Catcher", "VersionDecoder"]

import logging
import random
import weakref

from os import linesep

from snmp.ber import ParseError
from snmp.exception import IncomingMessageError
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
