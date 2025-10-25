:orphan:

Getting Started with SNMPv1 and SNMPv2c
=======================================

The first step in any SNMP application is to create an :class:`Engine<snmp.Engine>` object. The `defaultVersion` argument to the :class:`Engine<snmp.Engine>`\ 's constructor will tell the :class:`Engine<snmp.Engine>` what SNMP version to use as the default for the :meth:`Manager()<snmp.Engine.Manager>` method. You may also specify a default community using the `defaultCommunity` argument. The default community string is ``b"public"``.

.. code-block:: python

   from snmp import Engine, SNMPv1
   engine = Engine(SNMPv1)

In order to send SNMP requests, you will need to create a Manager object. Each
Manager represents a communication channel between your application and a single
remote engine (i.e. an Agent), so you will need more than one Manager to manage
multiple nodes.

You can create a Manager by calling :meth:`Engine.Manager()<snmp.Engine.Manager>`. For the purposes of this tutorial, you should provide a single argument, containing the IPv4 address of the remote engine. If the remote engine is listening on a non-standard port, then you may instead use a tuple, containing the address and port number. This method also defines a `version` parameter, to override the default given in the constructor, as well as a `community` parameter, which gives the Manager a different default community than the :class:`Engine<snmp.Engine>`-level default.

The variable referencing the Manager object should use a name that clearly
identifies the engine that it manages, such as in the following example:

.. code-block:: python

   localhost = engine.Manager("127.0.0.1")

Finally, you may send a request using one of the Manager's four request methods: :meth:`get()<SimplifiedSnmpManager.get>`, :meth:`getNext()<SimplifiedSnmpManager.getNext>`, :meth:`getBulk()<SimplifiedSnmpManager.getBulk>`, and :meth:`set()<SimplifiedSnmpManager.set>`.  The ``get*()`` methods accept any number of :class:`str` or :class:`snmp.smi.OID` arguments, representing the OIDs for the request. Each argument to the :meth:`set()<SimplifiedSnmpManager.set>` method may be either a :class:`snmp.smi.VarBind`, or a ``(name, value)`` tuple, where ``name`` is the OID (:class:`str` or :class:`snmp.smi.OID`), and ``value`` is an :mod:`snmp.smi` type. In all cases, the result will be a :class:`snmp.smi.VarBindList`.

The following example combines all the steps described above to query the
``sysContact`` and ``sysLocation`` of an SNMP engine listening on the loopback
address.

.. note::

   This code will run out of the box on an Ubuntu machine. All you have to do is
   install the snmp daemon with ``sudo apt install snmpd``.

.. code-block:: python

   from snmp import *

   engine = Engine(SNMPv1)  # or SNMPv2c
   localhost = engine.Manager("127.0.0.1", community=b"public")
   response = localhost.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
   print(response)

The output of this example should look something like this:

.. code-block:: console

   1.3.6.1.2.1.1.4.0: OctetString(b'Me <me@example.org>')
   1.3.6.1.2.1.1.6.0: OctetString(b'Sitting on the Dock of the Bay')
