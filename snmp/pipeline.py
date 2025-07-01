__all__ = ["Catcher", "VersionDecoder"]

import logging
import random
import re
import weakref

from os import linesep

from snmp.exception import *
from snmp.message import *
from snmp.utils import *

class Catcher:
    def __init__(self, listener, verbose=False):
        self.listener = listener
        self.logger = logging.getLogger(__name__.split(".")[0])
        self.verbose = verbose

        self.packets = 0

    def hear(self, data: bytes, channel) -> None:
        self.packets += 1

        try:
            self.listener.hear(data, channel)
        except IncomingMessageErrorWithPointer as err:
            if self.verbose:
                self.logger.debug(f"{typename(err)}:{err}{linesep}{err.data}")
        except IncomingMessageError as err:
            if self.verbose:
                hexdump = re.sub(r"(?<=.{2})(.{2})", r" \1", data.hex())
                self.logger.debug(f"{err!r}{linesep}{hexdump}")
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
