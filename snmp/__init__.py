"""An implementation of the Simple Network Management Protocol

This library provides a pure-Python implementation of the Simple Network
Management Protocol. It is designed primarily for ease of use, with a
secondary goal of minimizing resource usage, specifically in the number
of threads and the amount of network traffic.

.. note::

    The current library version only supports the role of Command
    Generator (i.e. a Manager that is not capable of processing Traps).
    Support for additional roles will be added in later versions.
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
