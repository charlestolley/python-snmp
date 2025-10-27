The SNMP Engine
===============

It's difficult to give a good definition for the term "SNMP Engine." The important thing to understand is that the first step in any SNMP application is to instantiate an :class:`Engine` object. You should never need more than one.

.. module:: snmp

.. data:: SNMPv1

   Protocol ID for SNMP version 1.

.. data:: SNMPv2c

   Protocol ID for SNMP version 2 with community-based authentication.

.. data:: SNMPv3

   Protocol ID for SNMP version 3.

.. data:: UDP_IPv4

   Transport domain ID for UDP over IPv4.

.. data:: UDP_IPv6

   Transport domain ID for UDP over IPv6.

.. data:: noAuthNoPriv

   Messages at this security level are neither encrypted nor signed.

.. data:: authNoPriv

   Messages at this security level are signed but not encrypted.

.. data:: authPriv

   Messages at this security level are signed and their payloads are encrypted.

.. class:: Engine( \
      defaultVersion: SNMPv1 | SNMPv2c | SNMPv3 = SNMPv3, \
      defaultDomain: UDP_IPv4 | UDP_IPv6 = UDP_IPv4, \
      defaultCommunity: bytes = b"public", \
      autowait: bool = True, \
      verboseLogging: bool = False, \
   )

   .. warning::

      This constructor does not allow positional arguments except for the `defaultVersion` parameter; all other arguments must be passed by keyword. Any future changes to the ordering of these keyword-only parameters will be considered non-breaking.

   The `defaultVersion`, `defaultDomain`, `defaultCommunity`, and `autowait` parameters set the default `version`, `domain`, `community`, and `autowait` arguments (respectively) for the :meth:`Manager` method.

   The `verboseLogging` parameter causes the :class:`Engine` to generate a detailed log message for each incoming packet that it discards. Each log message contains a representation of the packet, as well as an explanation of why it was discarded. These messages are then logged using ``logging.getLogger("snmp").debug()``. You, the caller, are responsible for configuring the :mod:`logging` module to output these messages to the location, and in the format, of your choosing. This must be done prior to creating the :class:`Engine`. In the simplest case, you can simply call ``logging.basicConfig()``:

   .. code-block:: python

      import logging
      import snmp

      logging.basicConfig(level=logging.DEBUG)
      engine = snmp.Engine(verboseLogging=True)

   The :class:`Engine` class is not thread-safe. All method calls to Managers and :class:`RequestHandle`\ s must be done in a single thread.

   .. py:method:: addUser( \
         user: str, \
         namespace: str = "", \
         default: bool = None, \
         authProtocol = None, \
         privProtocol = None, \
         authSecret: bytes = None, \
         privSecret: bytes = None, \
         secret: bytes = None, \
         defaultSecurityLevel = None, \
      )

      Store the authentication and privacy algorithms and passwords for a `user`. If the `user` is already defined, calling :meth:`addUser` will overwrite the stored configuration.

      The `authProtocol` and `authSecret` parameters configure the authentication algorithm and password, and the `privProtocol` and `privSecret` parameters configure the privacy algorithm and password. If the `user` only has one password (either because the two passwords are the same, or because the user does not support privacy), you can omit `authSecret` and `privSecret`, and just use `secret`. Here are some examples of valid ways to configure users.

      .. code-block:: python

         from snmp import *
         from snmp.security.usm.auth import *
         from snmp.security.usm.priv import *

         engine = Engine()

         engine.addUser(
            "user1",
            authProtocol=HmacSha256,
            authSecret=b"auth secret",
         )

         engine.addUser(
            "user2",
            authProtocol=HmacSha384,
            secret=b"auth secret",
         )

         engine.addUser(
            "user3",
            authProtocol=HmacSha,
            privProtocol=AesCfb128,
            authSecret=b"authentication secret",
            privSecret=b"privacy secret",
         )

         engine.addUser(
            "user4",
            authProtocol=HmacMd5,
            privProtocol=DesCbc,
            authSecret=b"12345",
            privSecret=b"12345",
         )

         engine.addUser(
            "user5",
            authProtocol=HmacSha224,
            privProtocol=AesCfb128,
            secret=b"shared secret",
         )

      .. warning::

         While the `user` and `namespace` parameters are both :class:`str`\ s, all passwords must be :class:`bytes`.

      Defaults
      --------

      The `default` parameter sets the `user` as the default user name for new SNMPv3 Managers. The first user added to a new :class:`Engine` automatically becomes the default, but you can override this in any future :meth:`addUser` call by setting `default` to ``True``.

      The :class:`Engine` also keeps track of the default security level for each user. By default, it select the highest available security level (e.g. if `authProtocol` is `HmacSha512`, but `privProtocol` is ``None``, the default security level will be ``authNoPriv``), but you can override this (with a lower security level only) using the `defaultSecurityLevel` parameter.

      Namespaces
      ----------

      Everything I've read about SNMP security seems to assume that a user only has one set of algorithms and passwords, which are deployed on every machine in your network. In real life, however, there are plenty of reasons why this might not be the case, like if you inherit hardware from another department, or if you are in the process of updating 100 machines, but you've only finished 9 so far.

      Under the namespace model (which I believe is unique to this library), you should sort all the machines in your network into groups, so that every machine in a group has compatible credentials. Give each group a name. In each call to :meth:`addUser`, give, as the `namespace` argument, the name of the group that accepts those credentials. Then, when you call :meth:`Manager`, give, as the `namespace` argument, the name of the group that the machine belongs to. Each time the Manager has to prepare a request for that machine, it will pass the user name and namespace to the :class:`Engine`, and it will find the version of that user's credentials that will work on that machine.

      Note that an :class:`Engine` does not simply have one default user name, but in fact has a default user name for each namespace. If you ignore the existence of the `namespace` argument, then every user will be added to the default ``""`` namespace, giving the illusion of a single default for the whole :class:`Engine`.

   .. py:method:: Manager( \
         address, \
         version = SNMPv3, \
         domain = None, \
         localAddress = None, \
         mtu = None, \
         autowait = None, \
         namespace = "", \
         defaultUser = None, \
         defaultSecurityLevel = None, \
      ) -> SNMPv3Manager
      Manager( \
         address, \
         version = SNMPv2c, \
         domain = None, \
         localAddress = None, \
         mtu = None, \
         autowait = None, \
         community = None, \
      ) -> SNMPv2cManager
      Manager( \
         address, \
         version = SNMPv1, \
         domain = None, \
         localAddress = None, \
         mtu = None, \
         autowait = None, \
         community = None, \
      ) -> SNMPv1Manager

      .. warning::

         This method allows positional arguments for the `address` and `version` parameters only; all other arguments must be passed by keyword. Any future changes to the ordering of these keyword-only parameters will be considered non-breaking.

      This `Factory Method`_ creates Manager objects (i.e. objects implementing the :class:`SnmpManager` interface), which you can use to send SNMP requests to remote engines. There are three different signatures for this method, depending on the version argument. Several parameters are common to all three signatures; the other parameters are version-specific.

      Version-Independent Parameters
      ------------------------------

      The `domain` parameter selects the transport domain over which the Manager will communicate. The possible values are :data:`UDP_IPv4` and :data:`UDP_IPv6`. The `address` parameter provides the transport address of the remote engine with which the Manager will communicate (as mentioned elsewhere, each Manager object communicates with exactly one remote engine). The `localAddress` allows you to select a specific IP address and port on your local machine from which to send requests. These parameters both accept either a :class:`str`, or a :class:`tuple[str, int]`. The :class:`str` contains the network address, and the :class:`int` (if included) gives the port number. The default port number for the `address` parameter is ``161``, which is the standard well-known UDP port for SNMP requests. The default `localAddress` is ``("0.0.0.0", 0)`` for :data:`UDP_IPv4`, and ``("::", 0)`` for :data:`UDP_IPv6`. The port number ``0`` causes the Manager to select a random available port to use as the source port for requests. This selection happens only once; after that, the port number does not change. The :class:`str` in the default `localAddress` instructs the Manager to listen on all network interfaces for the remote engine's reply.

      The `mtu` parameter allows you to tell the Manager about the Maximum Transmission Unit size of the network interface that corresponds to your selected `localAddress`. This impacts the maximum SNMP message size that the Manager will accept in a reply. The default value is ``1500``, which is the maximum payload size of a standard Ethernet frame, and should be suitable for nearly all use-cases. The `mtu` argument must have the same value for all Managers with the same `localAddress`.

      The `autowait` parameter sets the default `wait` argument for the Manager's request functions (see :meth:`SnmpManager.get`). The default for `autowait` comes from the :class:`Engine` constructor, which has ``True`` as the default value. Consequently, the default behavior is for every request method call to block until the response is received, and then return the :class:`VarBindList<snmp.smi.VarBindList>` from the response.

      .. code-block:: python

         import snmp

         engine = snmp.Engine()
         manager = engine.Manager("127.0.0.1")

         # Block until the response arrives
         vblist = manager.get("1.3.6.1.2.1.1.1.0")

      Version-Specific Parameters
      ---------------------------

      SNMPv3
      ******

      See the Namespaces_ section, above, for an explanation of the `namespace` parameter.

      .. warning::

         Before creating a Manager, you should call :meth:`addUser` to configure all the credentials your Manager will need.

      .. note::

         It is not necessary to call :meth:`addUser` before :meth:`Manager` if the Manager will only be used to make ``noAuthNoPriv`` requests. In this case, however, the `defaultUser` argument is required.

      The `defaultUser` parameter sets the default user name for the Manager. If the `defaultUser` argument is ``None``, the Manager will use the default user name configured for this namespace (see the Defaults_ section above, as well as the last paragraph of the Namespaces_ section).

      The `defaultSecurityLevel` parameter sets the default security level for the Manager. If the `defaultSecurityLevel` is ``None``, the Manager will use the default security level configured for this user (see the Defaults_ section above).

      SNMPv1/SNMPv2c
      **************

      The `community` parameter sets the default community name for all request methods. The default for this parameter is to use the `defaultCommunity` from the :class:`Engine` constructor.

   .. py:method:: poll(*handles: RequestHandle) -> RequestPoller

      Create a poller object to :meth:`wait()<RequestPoller.wait>` on multiple :class:`RequestHandle`\ s at once.

      If you provide one or more `handles` in the argument list, the call will :meth:`register()<RequestPoller.register>` them for you before returning the :class:`RequestPoller` object.

.. _Factory Method: https://en.wikipedia.org/wiki/Factory_method_pattern

