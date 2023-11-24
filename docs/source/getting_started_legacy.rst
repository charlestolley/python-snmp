:orphan:

Getting Started with SNMPv1 and SNMPv2c
=======================================

The first step in any SNMP application is to create an Engine object. It is
important to declare the Engine in a ``with`` statement, in orderly to properly
clean up background threads and network resources. The ``defaultVersion``
argument to the Engine's constructor will tell the Engine what SNMP version to
use as the default for the ``Manager()`` method. You may also specify a default
community using the ``defaultCommunity`` argument.

.. code-block:: python

   from snmp import Engine, SNMPv2c

   with Engine(SNMPv2c, defaultCommunity="public") as engine:
       # This block will contain the entire SNMP application
       ...

In order to send SNMP requests, you will need to create a Manager object. Each
Manager represents a communication channel between your application and a single
remote engine (i.e. an Agent), so you will need more than one Manager to manage
multiple nodes.

You can create a Manager by calling :meth:`Engine.Manager`. For the purposes of
this tutorial, you should provide a single argument, containing the IPv4 address
of the remote engine. If the remote engine is listening on a non-standard port,
then you may instead use a tuple, containing the address and port number. This
method also includes a ``version`` argument, to override the default given in
the constructor, as well as a ``community`` argument, which gives the Manager a
different default community than the Engine-level default.

A variable containing a Manager object should use a name that clearly identifies
the engine that it manages, such as in the following example:

.. code-block:: python

   localhost = engine.Manager("127.0.0.1")

Finally, you may send a request using one of the Manager's three (or four)
request methods: ``get()``, ``getNext()``, ``getBulk()`` (only availble for
SNMPv2c), and ``set()``.  The ``get*()`` methods accept any number of
:class:`str` or :class:`snmp.types.OID` arguments, while the ``set()`` method
accepts arguments of type :class:`snmp.pdu.VarBind`. In all cases, the result
will be a :class:`snmp.pdu.ResponsePDU`.

The following example combines all the steps described above to query the
``sysContact`` and ``sysLocation`` of an SNMP engine listening on the loopback
address.

.. note::

   This code will run out of the box on an Ubuntu machine. All you have to do is
   install the snmp daemon with ``sudo apt install snmpd``.

.. code-block:: python

   from snmp import Engine, SNMPv2c
   
   with Engine(SNMPv2c, defaultCommunity=b"public") as engine:
       localhost = engine.Manager("127.0.0.1")
       response = localhost.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
       print(response)

The output of this example should look something like this:

.. code-block:: console

   ResponsePDU:
       Request ID: 560757371
       Error Status: 0
       Error Index: 0
       Variable Bindings:
           1.3.6.1.2.1.1.4.0: OctetString(b'Me <me@example.org>')
           1.3.6.1.2.1.1.6.0: OctetString(b'Sitting on the Dock of the Bay')
