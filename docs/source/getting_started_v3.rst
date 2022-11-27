Getting Started with SNMPv3
===========================

The first step in any SNMP application is to create an Engine object. It is important to declare the Engine in a ``with`` statement, in orderly to properly clean up background threads and network resources.

.. code-block:: python

    from snmp import Engine

    with Engine() as engine:
        # This block will contain the entire SNMP application
        ...

In order to send SNMP requests, you will need to create a Manager object. Each Manager represents a communication channel between your application and a single remote engine (i.e. an Agent), so you will need more than one Manager to manage multiple nodes.

Before creating a Manager, however, you must provide the Engine with credentials for the user(s) belonging to the engine that it manages. The ``Engine.usm.addUser()`` method tells the Engine about the algorithm(s) and password(s) for each user. The :mod:`snmp.security.usm.auth` and :mod:`snmp.security.usm.priv` modules contain implementations of several common authentication and privacy (encryption) algorithms.

.. note::

   The :mod:`snmp.security.usm.priv` module is considered optional, because it requires OpenSSL. If you are unable to import this module, it likely indicates that something went wrong in the installation. The :doc:`installation` page may help in resolving the issue.

As an example, imagine a user ``"admin"`` that supports authentication using ``HMAC-SHA-256`` and privacy using ``CFB128-AES-128``, with ``"maplesyrup"`` as the password for both. Here's what the call to ``addUser()`` would look like:

.. code-block:: python

    from snmp import Engine
    from snmp.security.usm.auth import HmacSha256
    from snmp.security.usm.priv import Aes128Cfb

    with Engine() as engine:
        engine.usm.addUser(
            "admin",
            authProtocol=HmacSha256,
            privProtocol=Aes128Cfb,
            secret=b"maplesyrup",
        )

In this example, the user has one password for both authentication and privacy. However, it is also possible to provide two separate passwords with the ``authSecret`` and ``privSecret`` arguments, rather than using the ``secret`` argument. Further, note that the first argument, ``userName``, accepts a :class:`str`, while all passwords are expected to be of type :class:`bytes`. A justification of this behavior is beyond the scope of this document.

After providing the necessary user configuration via the ``addUser()`` method, you may create a Manager by calling :meth:`Engine.Manager`. For the purposes of this tutorial, you should provide a single argument, containing the IPv4 address of the remote engine. If the remote engine is listening on a non-standard port, then you may instead use a tuple, containing the address and port number. A variable containing a Manager object should use a name that clearly identifies the engine that it manages, such as in the following example:

.. code-block:: python

    localhost = engine.Manager("127.0.0.1")

Finally, you may send a request using one of the Manager's four request methods: ``get()``, ``getNext()``, ``getBulk()``, and ``set()``. The ``get*()`` methods accept any number of :class:`str` or :class:`snmp.types.OID` arguments, while the ``set()`` method accepts arguments of type :class:`snmp.pdu.VarBind`. In all cases, the result will be a :class:`snmp.pdu.ResponsePDU`.

The following example combines all the steps described above to query the ``sysContact`` and ``sysLocation`` of an SNMP engine listening on the loopback address.

.. note::

   This code will run out of the box on an Ubuntu machine with just a few simple setup steps (as the root user). First, install the snmp daemon with ``apt install snmpd``. Then edit ``/etc/snmp/snmpd.conf``, and uncomment the line that says ``createuser authPrivUser SHA-512 myauthphrase AES myprivphrase`` (or add it, if it's not there). Save and exit that file, and then run ``systemctl restart snmpd``.

.. code-block:: python

    from snmp import Engine
    from snmp.security.usm.auth import HmacSha512
    from snmp.security.usm.priv import Aes128Cfb
    
    with Engine() as engine:
        engine.usm.addUser(
            "authPrivUser",
            authProtocol=HmacSha512,
            authSecret=b"myauthphrase",
            privProtocol=Aes128Cfb,
            privSecret=b"myprivphrase",
        )
    
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
