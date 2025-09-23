The SNMP Engine
===============

It's difficult to give a good definition for the term "SNMP Engine." The important thing to understand is that the first step in any SNMP application is to instantiate an Engine object. You should never need more than one.

.. module:: snmp

.. data:: SNMPv1

   SNMP version 1.

.. data:: SNMPv2c

   SNMP version 2 with community-based authentication.

.. data:: SNMPv3

   SNMP version 3.

.. data:: UDP_IPv4

   Messages in this transport domain are sent as UDP datagrams over an IPv4
   network.

.. data:: UDP_IPv6

   Messages in this transport domain are sent as UDP datagrams over an IPv6
   network.

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

   The `verboseLogging` parameter causes the ``Engine`` to generate a detailed log message for each incoming packet that it discards. Each log message contains a representation of the packet, as well as an explanation of why it was discarded. These messages are then logged using ``logging.getLogger("snmp").debug()``. You, the caller are responsible for configuring the ``logging`` module to output these messages to the location, and in the format, of your choosing. This must be done prior to creating the ``Engine``. In the simplest case, you can simply call ``logging.basicConfig()``:

   .. code-block:: python

      import logging
      import snmp

      logging.basicConfig(level=logging.DEBUG)
      engine = snmp.Engine(verboseLogging=True)

   .. py:method:: addUser( \
         user, \
         namespace = "", \
         default = None, \
         authProtocol = None, \
         privProtocol = None, \
         authSecret = None, \
         privSecret = None, \
         secret = None, \
         defaultSecurityLevel = None, \
      )

      Store the (User-Based Security Model) security configuration for a user. As used here, the phrase "security configuration" refers to the combination of

      - user name
      - authentication algorithm
      - privacy algorithm
      - authentication password
      - privacy password
      - default security level

      Each user name is unique (within a namespace), so calling addUser() twice with the same user name (and namespace) will overwrite the previous security configuration.

      The namespace is a made-up construct, specific to this library, that enables you to distinguish between different security configurations with the same user name. This is only useful for an application that manages multiple nodes with different credentials for the same user name (e.g. host1 defines user1, using HmacMd5 with password "foo", while host2 defines user1 using HmacSha with password "bar"). If the nodes in your network all use the same algorithms and passwords for each user name, then you should simply ignore the namespace argument.

      .. note::

         The purpose of the namespace construct is not to organize the security configurations, but to organize the managed nodes (i.e. remote engines) in the network. A namespace should represent the set of all nodes that share the same set of security configurations.

      Each namespace (including the default "" namespace) has a default user name. The first user added to a namespace automatically becomes the default. To override the default in a later call to addUser(), simply use default=True.

      The authProtocol and privProtocol parameters assign the authentication and privacy algorithms for the security configuration. Each parameter expects a class, and not an instance of a class. The snmp.security.usm.auth and snmp.security.usm.priv modules define classes for each of the standard algorithms.

      .. note::

         Consult the Installation page if you are unable to import snmp.security.usm.priv.

      The authSecret and privSecret parameters assign the authentication and privacy passwords to go along with the configured algorithms. Each password must be a byte string, and not a unicode string (i.e. it's type must be bytes). If the two passwords are the same, you can optionally use the secret parameter in place of authSecret and privSecret. Similarly, if privProtocol is None, you can use secret in place of authSecret.

      Finally, the default security level for the security configuration can be manually assigned using the defaultSecurityLevel parameter. If this parameter is None, then the highest supported security level will be selected as the default (e.g. if privProtocol is None, but authProtocol is not None, then the highest supported security level is authNoPriv).

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

         This method only allows positional arguments for the `address` and `version` parameters; all other arguments must be passed by keyword. Any future changes to the ordering of these keyword-only parameters will be considered non-breaking.

      This `Factory Method`_ creates Manager objects (i.e. objects implementing the Manager Interface), which you can use to send SNMP requests to remote engines. This section does not explain how to use a Manager object -- there are two other sections dedicated to that -- it simply explains how to create one. There are three different signatures for this method, depending on the version argument. Several parameters are common to all three signatures; the other parameters are version-specific.

      Version-Independent Parameters
      ------------------------------

      The domain parameter selects the transport domain over which the Manager will communicate. The possible values are UDP_IPv4 or UDP_IPv6. The address parameter provides the transport address of the remote engine with which the Manager will communicate. As explained in the Manager Interface section, each Manager object communicates with exactly one remote engine. The localAddress allows you to select a specific interface on your local machine. These parameters both accept either a str, or a (str, int) tuple. The str contains the network address, and the int portion (if included) gives the port number. The default port number for the address parameter is 161, which is the standard well-known UDP port for SNMP requests. The default localAddress is ("0.0.0.0", 0) for UDP_IPv4, and ("::", 0) for UDP_IPv6. The zero port number causes the Manager to select a random available port number to use as the source port for requests. This selection happens only once; after that, the port number does not change. The string portion of the default localAddress instructs the Manager to listen on all network interfaces for the remote engine's reply.

      The mtu parameter allows you to tell the Manager about the Maximum Transmission Unit size of the network interface that corresponds to your selected localAddress. This impacts the maximum SNMP message size that the Manager will accept in a reply. The default value is 1500, which is the maximum payload size of a standard Ethernet frame, and should be suitable for nearly all use-cases. The mtu argument must have the same value for all Managers with the same localAddress.

      The autowait parameter sets the default wait argument for the Manager's request functions (see the complete Manager Interface documentation). The default for autowait comes from the Engine constructor, with a default of False. Consequently, the default behavior is for every request method call to block until the response is received, at which point it will return the VarBindList from the response.

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

      The addUser() method allows you to organize the users and credentials into namespaces. This method's namespace parameter allows you to select a namespace for this Manager. When you send a request with authentication or privacy, the Manager will look up the security configuration within this namespace, and use those credentials to sign and/or encrypt the message, and to verify and/or decrypt the response.

      .. note::

         In order to use security features, you must define at least one user in the Manager's namespace, by calling Engine.addUser(), before creating your Manager object. In spite of the "at least" in the previous sentence, it's best to just add all security configurations up front. If you are not using security, then you do not need to call Engine.addUser(), so long as you specify a defaultUser when you create your Manager.

      The defaultUser and defaultSecurityLevel parameters assign default values for the user name and securityLevel arguments to the request methods. If you do not specify a defaultUser, but there is at least one user configured in the chosen namespace, then the Manger will inherit the default user from the namespace. Otherwise, if no defaultUser is given, the method will raise a TypeError. The defaultSecurityLevel will be inferred in all cases, based on the highest securityLevel that the defaultUser supports. The Manager stores both of these defaults internally, meaning that later calls to Engine.addUser() will not affect the default user name or securityLevel of existing Manager objects.

      On the other hand (and as a bit of an aside), be aware that changes to the configured algorithms and passwords WILL be reflected in subsequent requests. The following example changes all of these things, to highlight which changes matter to the Manager, and which don't.

      .. code-block:: python

         from snmp import *
         from snmp.security.usm.auth import *
         from snmp.security.usm.priv import *

         engine = Engine()
         engine.addUser("chuck", authProtocol=HmacSha256, authSecret=b"wrong")

         manager = engine.Manager("127.0.0.1")

         try:
            print(manager.getNext("1.3.6.1.2.1.2.2.1.2"))
         except Exception:
            engine.addUser(
               "chuck",
               authProtocol=HmacSha256,
               privProtocol=AesCfb128,
               secret=b"right",
            )

            engine.addUser("other", default=True)
            print(manager.getNext("1.3.6.1.2.1.2.2.1.2"))

      If you were to run this example (substituting the user name, authProtocol, and authSecret for valid ones), along with a packet capture, you would see two requests, both for user "chuck", and both with authNoPriv. This demonstrates that the addition of the "other" user does not change the Manager's default user name or securityLevel, nor does the addition of a privProtocol for user "chuck" change the default securityLevel. As for the responses, the first would indicate an invalid digest (signature), and the second would succeed. This demonstrates that the new authProtocol and secret are both being used. Note that if the second getNext() request had manually specified a securityLevel of authPriv, then the new privProtocol would have been used as well.

      SNMPv1/SNMPv2c
      **************

      The `community` parameter sets the default community name for all request methods. The default for this parameter is to use the defaultCommunity from the Engine constructor.

.. _Factory Method: https://en.wikipedia.org/wiki/Factory_method_pattern

