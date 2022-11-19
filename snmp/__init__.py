"""This library implements the Simple Network Management Protocol (SNMP).
In spite of it's name, SNMP seems to have a reputation for being
complicated and unintuitive. This library aims to make it as easy as
possible to use SNMP in Python.

   .. note::

      The current version is, admittedly, somewhat limited in its features.
      It currently only supports the "CommandGenerator" role, which allows
      the user to send requests and receive responses. At this time, there
      is no interface for generating or processing traps, or for accepting
      requests, but those features will be supported in time.
"""

__all__ = [
    "Engine",
    "SNMPv1", "SNMPv2c", "SNMPv3",
    "noAuthNoPriv", "authNoPriv", "authPriv",
]

from snmp.engine import Engine
from snmp.message import MessageProcessingModel
from snmp.security.levels import *

SNMPv1  = MessageProcessingModel.SNMPv1.value
SNMPv2c = MessageProcessingModel.SNMPv2c.value
SNMPv3  = MessageProcessingModel.SNMPv3.value
