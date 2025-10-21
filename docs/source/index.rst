SNMP with Python
================

Welcome to the ``snmp`` library documentation! This library focuses on making
the Simple Network Management Protocol as simple-to-use as possible. If you are
new to ``snmp``, you can see the basic usage in the examples below. For an
explanation of these examples, see the :doc:`getting_started` section.

For a complete list of available features, and a precise description of their
behavior, consult the :doc:`Library Reference<library>`.

Installation
------------

The simplest way to install ``snmp`` is with ``pip``:

.. code-block:: console

   pip install snmp

See the :doc:`installation` section for advanced options.

Examples
--------

SNMPv3 Example
**************

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

SNMPv1/SNMPv2c Example
**********************

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

.. toctree::
   :hidden:

   installation
   getting_started
   library
