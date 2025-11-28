Getting Started
===============

.. note::

   This document only covers SNMP version 3, there is a separate document for
   :doc:`getting_started_legacy`.

The first step in any SNMP application is to create an :class:`Engine<snmp.Engine>` object:

.. code-block:: python

   from snmp import Engine
   engine = Engine()

In order to send SNMP requests, you will need to create a Manager object. Each
Manager represents a communication channel between your application and a single
remote engine (i.e. an Agent), so you will need more than one Manager to manage
multiple nodes.

Before creating a Manager, however, you must provide the :class:`Engine<snmp.Engine>` with credentials for the user(s) belonging to the engine that it manages. The :meth:`Engine.addUser()<snmp.Engine.addUser>` method tells the :class:`Engine<snmp.Engine>` about the algorithm(s) and
password(s) for each user. The :mod:`snmp.security.usm.auth` and
:mod:`snmp.security.usm.priv` modules contain implementations of several common
authentication and privacy (encryption) algorithms.

.. note::

   The :mod:`snmp.security.usm.priv` module is considered optional, because it
   relies on third-party libraries. See the :doc:`installation` section for more
   information.

As an example, imagine a user ``"admin"`` that supports authentication using ``HMAC-SHA-256`` and privacy using ``CFB128-AES-128``, with ``"maplesyrup"`` as the password for both. Here's what the call to :meth:`addUser()<snmp.Engine.addUser>` would look like:

.. code-block:: python

   from snmp import Engine
   from snmp.security.usm.auth import HmacSha256
   from snmp.security.usm.priv import AesCfb128

   engine.addUser(
       "admin",
       authProtocol=HmacSha256,
       privProtocol=AesCfb128,
       secret=b"maplesyrup",
   )

In this example, the user has one password for both authentication and privacy.  However, it is also possible to provide two separate passwords using the `authSecret` and `privSecret` parameters, rather than the `secret` parameter. Further, note that the first parameter, `user`, accepts a :class:`str`, while all passwords are expected to be of type :class:`bytes`. A justification for this design is beyond the scope of this document.

After providing the necessary user configuration via the :meth:`addUser()<snmp.Engine.addUser>` method, you can create a Manager by calling :meth:`Engine.Manager()<snmp.Engine.Manager>`. For the purposes of this tutorial, you should provide a single argument, containing the IPv4 address of the remote engine. If the remote engine is listening on a non-standard port, then you may instead use a tuple, containing the address and port number. The variable referencing the Manager object should use a name that clearly identifies the engine that it manages, such as in the following example:

.. code-block:: python

   localhost = engine.Manager("127.0.0.1")

Finally, you may send a request using one of the Manager's four request methods: :meth:`get()<SimplifiedSnmpManager.get>`, :meth:`getNext()<SimplifiedSnmpManager.getNext>`, :meth:`getBulk()<SimplifiedSnmpManager.getBulk>`, and :meth:`set()<SimplifiedSnmpManager.set>`. The ``get*()`` methods accept any number of :class:`str` or :class:`snmp.smi.OID` arguments, representing the OIDs for the request. Each argument to the :meth:`set()<SimplifiedSnmpManager.set>` method may be either a :class:`snmp.smi.VarBind`, or a ``(name, value)`` tuple, where ``name`` is the OID (:class:`str` or :class:`snmp.smi.OID`), and ``value`` is an :mod:`snmp.smi` type. In all cases, the result will be a :class:`snmp.smi.VarBindList`.

The following example combines all the steps described above to query the
``sysContact`` and ``sysLocation`` of an SNMP engine listening on the loopback
address.

.. note::

   This code will run out of the box on an Ubuntu machine with just a few simple
   setup steps (as the root user). First, install the snmp daemon with ``apt
   install snmpd``. Then open ``/etc/snmp/snmpd.conf``, and uncomment the line
   that says ``createuser authPrivUser SHA-512 myauthphrase AES myprivphrase``
   (or add it, if it's not there). Save and exit that file, and then run
   ``systemctl restart snmpd``.

.. code-block:: python

   from snmp import Engine
   from snmp.security.usm.auth import HmacSha512
   from snmp.security.usm.priv import AesCfb128

   engine = Engine()
   engine.addUser(
      "authPrivUser",
      authProtocol=HmacSha512,
      authSecret=b"myauthphrase",
      privProtocol=AesCfb128,
      privSecret=b"myprivphrase",
   )

   localhost = engine.Manager("127.0.0.1")
   response = localhost.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
   print(response)

The output of this example should look something like this:

.. code-block:: console

   1.3.6.1.2.1.1.4.0: OctetString(b'Me <me@example.org>')
   1.3.6.1.2.1.1.6.0: OctetString(b'Sitting on the Dock of the Bay')

The :class:`AsyncEngine<snmp.async_engine.AsyncEngine>` class has a nearly identical API that supports ``async`` and ``await``.

.. code-block:: python

   import asyncio

   from snmp.async_engine import AsyncEngine
   from snmp.security.usm.auth import HmacSha512
   from snmp.security.usm.priv import AesCfb128

   engine = AsyncEngine()
   engine.addUser(
       "authPrivUser",
       authProtocol=HmacSha512,
       authSecret=b"myauthphrase",
       privProtocol=AesCfb128,
       privSecret=b"myprivphrase",
   )

   async def main(manager):
       response = await manager.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
       print(response)

   loop = asyncio.get_event_loop()
   localhost = engine.Manager("127.0.0.1")
   loop.run_until_complete(main(localhost))
