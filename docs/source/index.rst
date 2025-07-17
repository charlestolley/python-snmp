SNMP with Python
================

Welcome to the ``snmp`` library documentation! This library focuses on making
the Simple Network Management Protocol as simple-to-use as possible. If you are
new to ``snmp``, you can see the basic usage in the examples below. For an
explanation of these examples, see the :doc:`getting_started` section. For an
in-depth description of all available features, consult the ``snmp``
:doc:`Library Reference<snmp>`, which details the full public API.

Installation
------------

The simplest way to install ``snmp`` is with ``pip``:

.. code-block:: console

   pip install snmp

See the :doc:`installation` section for advanced options.

Examples
--------

.. note::

   This code will run out of the box on an Ubuntu machine with just a few simple
   setup steps (as the root user). To run the SNMPv1/SNMPv2c example, simply
   install the snmp daemon with ``apt install snmpd``. To run the SNMPv3
   example, you then need to edit ``/etc/snmp/snmpd.conf``, and uncomment the
   line that says ``createuser authPrivUser SHA-512 myauthphrase AES
   myprivphrase`` (or add it, if it's not there). Save and exit that file, and
   then run ``systemctl restart snmpd``.

SNMPv3 Example
**************

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

.. code-block:: python

   from snmp import *

   engine = Engine(SNMPv1)
   localhost = engine.Manager("127.0.0.1", community=b"public")
   response = localhost.get("1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0")
   print(response)

Note that the ``SNMPv1`` argument to ``Engine()`` simply sets the default
version for the ``Manager()`` factory method. You can still create an
``SNMPv2c`` or ``SNMPv3`` manager, with the ``version`` keyword parameter to the
``Manager()`` method (e.g.
``Manager("127.0.0.1", version=SNMPv2c, community=b"public")``).

Similarly, you can give the ``Engine`` a default community string with the
``defaultCommunity`` keyword parameter (e.g.
``Engine(SNMPv1, defaultCommunity=b"private")``. The default value for
``defaultCommunity`` is ``b"public"``.

The output should look like this (same as the other example):

.. code-block:: console

   1.3.6.1.2.1.1.4.0: OctetString(b'Me <me@example.org>')
   1.3.6.1.2.1.1.6.0: OctetString(b'Sitting on the Dock of the Bay')

.. toctree::
   :hidden:

   installation
   getting_started
   snmp
