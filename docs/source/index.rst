SNMP with Python
================

Welcome to the ``snmp`` library documentation! This library focuses on making
the Simple Network Management Protocol as simple-to-use as possible. If you are
new to ``snmp``, you can see the basic usage in the examples below. For an
explanation of these examples, see the :doc:`getting_started` section.

To learn about advanced features and options, consult the
:doc:`Library Reference<library>`.

Installation
------------

The simplest way to install ``snmp`` is with ``pip``:

.. code-block:: console

   pip install snmp

See the :doc:`installation` section for advanced options.

Examples
--------

SNMPv3 Manager Example
**********************

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

The output of this example should look like this:

.. code-block:: console

   1.3.6.1.2.1.1.4.0: OctetString(b'Me <me@example.org>')
   1.3.6.1.2.1.1.6.0: OctetString(b'Sitting on the Dock of the Bay')

This example can also be written in the async/await style, using an
:class:`AsyncEngine<snmp.async_engine.AsyncEngine>`.


.. code-block:: python

   import asyncio

   from snmp.async_engine import AsyncEngine
   from snmp.security.usm.auth import HmacSha512
   from snmp.security.usm.priv import AesCfb128

   async def main(manager):
       response = await manager.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
       print(response)

   engine = AsyncEngine()
   engine.addUser(
       "authPrivUser",
       authProtocol=HmacSha512,
       authSecret=b"myauthphrase",
       privProtocol=AesCfb128,
       privSecret=b"myprivphrase",
   )

   localhost = engine.Manager("127.0.0.1")

   loop = asyncio.get_event_loop()
   loop.run_until_complete(main(localhost))

SNMPv3 Trap Example
*******************

.. code-block:: python

   from snmp import *
   from snmp.security.usm.auth import *
   from snmp.security.usm.priv import *

   engine = Engine()
   engine.addUser(
       "authPrivUser",
       authProtocol=HmacSha,
       privProtocol=DesCbc,
       secret=b"mypassphrase",
   )

   traps = engine.TrapListener()

   while True:
       vblist, kwargs = traps.listen()

       print("\"{}\" received {} {} trap from {}".format(
           kwargs["user"],
           "an" if kwargs["securityLevel"].auth else "a",
           kwargs["securityLevel"],
           kwargs["address"][0],
       ))

       print(vblist)

When this program receives an SNMP Trap, it prints it out like this:

.. code-block:: console

   "authPrivUser" received an authPriv trap from 192.168.0.65
   1.3.6.1.2.1.1.3.0: TimeTicks(2413641)
   1.3.6.1.6.3.1.1.4.1.0: 1.3.6.1.4.1.9.9.43.2.0.1
   1.3.6.1.4.1.9.9.43.1.1.6.1.3.10: Integer32(1)
   1.3.6.1.4.1.9.9.43.1.1.6.1.4.10: Integer32(2)
   1.3.6.1.4.1.9.9.43.1.1.6.1.5.10: Integer32(3)

Here's an equivalent program using the
:class:`AsyncEngine<snmp.async_engine.AsyncEngine>`:

.. code-block:: python

   import asyncio

   from snmp.async_engine import AsyncEngine
   from snmp.security.usm.auth import *
   from snmp.security.usm.priv import *

   async def main(engine):
       traps = engine.TrapListener()

       while True:
           vblist, kwargs = await traps.listen()

           print("\"{}\" received {} {} trap from {}".format(
               kwargs["user"],
               "an" if kwargs["securityLevel"].auth else "a",
               kwargs["securityLevel"],
               kwargs["address"][0],
           ))

           print(vblist)

   engine = AsyncEngine()
   engine.addUser(
       "authPrivUser",
       authProtocol=HmacSha,
       privProtocol=DesCbc,
       secret=b"mypassphrase",
   )

   loop = asyncio.get_event_loop()
   loop.run_until_complete(main(engine))

SNMPv1/SNMPv2c Manager Example
******************************

.. note::

   This code will run out of the box on an Ubuntu machine. Simply install the
   snmp daemon with ``apt install snmpd``.

.. code-block:: python

   from snmp import *

   engine = Engine(SNMPv1)  # or SNMPv2c
   localhost = engine.Manager("127.0.0.1", community=b"public")
   response = localhost.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
   print(response)

The expected output is the same as that of the SNMPv3 example:

.. code-block:: console

   1.3.6.1.2.1.1.4.0: OctetString(b'Me <me@example.org>')
   1.3.6.1.2.1.1.6.0: OctetString(b'Sitting on the Dock of the Bay')

This example can also be written in the async/await style, using an
:class:`AsyncEngine<snmp.async_engine.AsyncEngine>`.

.. code-block:: python

   import asyncio

   from snmp import *
   from snmp.async_engine import AsyncEngine

   async def main(manager):
       response = await manager.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
       print(response)

   engine = AsyncEngine(SNMPv1)  # or SNMPv2c
   localhost = engine.Manager("127.0.0.1", community=b"public")

   loop = asyncio.get_event_loop()
   loop.run_until_complete(main(localhost))

SNMPv2c Trap Example
********************

.. code-block:: python

   from snmp import *

   engine = Engine(SNMPv2c)
   traps = engine.TrapListener()

   while True:
       vblist, kwargs = traps.listen()

       print("Received a trap from {} for {}".format(
           kwargs["address"][0],
           kwargs["community"],
       ))

       print(vblist)

When this program receives an SNMP Trap, it prints it out like this:

.. code-block:: console

   Received a trap from 192.168.0.65 for b'public'
   1.3.6.1.2.1.1.3.0: TimeTicks(2413641)
   1.3.6.1.6.3.1.1.4.1.0: 1.3.6.1.4.1.9.9.43.2.0.1
   1.3.6.1.4.1.9.9.43.1.1.6.1.3.10: Integer32(1)
   1.3.6.1.4.1.9.9.43.1.1.6.1.4.10: Integer32(2)
   1.3.6.1.4.1.9.9.43.1.1.6.1.5.10: Integer32(3)

Here's an equivalent program using the
:class:`AsyncEngine<snmp.async_engine.AsyncEngine>`:

.. code-block:: python

   import asyncio

   from snmp import *
   from snmp.async_engine import AsyncEngine

   async def main(engine):
       traps = engine.TrapListener()

       while True:
           vblist, kwargs = await traps.listen()

           print("Received a trap from {} for {}".format(
               kwargs["address"][0],
               kwargs["community"],
           ))

           print(vblist)

   engine = AsyncEngine(SNMPv2c)

   loop = asyncio.get_event_loop()
   loop.run_until_complete(main(engine))

.. toctree::
   :hidden:

   installation
   getting_started
   library
