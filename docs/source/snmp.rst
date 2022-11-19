:mod:`snmp` --- Simple Network Management Protocol
==================================================

.. automodule:: snmp

.. data:: SNMPv1
.. data:: SNMPv2c
.. data:: SNMPv3

   These enumerated values represent SNMP protocol versions in any method that
   accepts a `version` parameter. Their numerical values match those used in the
   `msgVersion` field of an SNMP message.

.. autoclass:: Engine
   :members:

.. data:: noAuthNoPriv
   :canonical: snmp.security.levels.noAuthNoPriv

.. data:: authNoPriv
   :canonical: snmp.security.levels.authNoPriv

.. data:: authPriv
   :canonical: snmp.security.levels.authPriv

   These objects represent the three possible security levels in SNMP version 3.
