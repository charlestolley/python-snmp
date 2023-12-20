:mod:`snmp` --- Simple Network Management Protocol
==================================================

.. module:: snmp

   This library contains an implementation of the Simple Network Management
   Protocol (SNMP). In spite of it's name, SNMP seems to have a reputation for
   being complicated and confusing. This design of this library places high
   priority on usability in hopes of alleviating this confusion. Class and
   method names also use many of the same terms found in the standards
   documents, so that someone can easily read the source code and the standards
   together and feel they are speaking the same language.

   .. note::

      This library is still under development. It currently supports the
      "CommandGenerator" role, which allows the user to send requests and
      receive responses. Future versions will add support for sending and
      receiving notifications (i.e. traps), and for accepting incoming
      requests.

   While this reference does roughly follow a logical order, its top focus is on
   thoroughness or completeness. For a proper tutorial, see the
   :doc:`getting_started` page.

.. class:: Engine( \
      defaultVersion=SNMPv3, \
      defaultDomain=TransportDomain.UDP_IPv4, \
      defaultSecurityModel=SecurityModel.USM, \
      defaultCommunity=b"", \
      msgMaxSize=1472, \
      autowait=True, \
   )
   :canonical: snmp.engine.Engine

   Technically speaking, this class is a Facade_ for the various components in
   this library. Because it manages network resources and background threads, it
   is important to properly close it at the end of its life. The recommended way
   to do this is with a context manager (e.g. ``with Engine() as engine``). The
   alternative is to call :meth:`shutdown` directly at the end of the
   :class:`Engine`'s useful life. The latter approach is most useful for
   interactive settings, such as a Python interactive shell session.

   The `msgMaxSize` parameter configures the maximum message size that this
   :class:`Engine` is capable of receiving. The other parameters configure the
   default arguments to the :meth:`Manager` factory method. `defaultVersion` is
   the only positional parameter. All other parameters should be passed by
   keyword, as their ordering is subject to change in future library versions.

   .. note::

      Not only is User-Based security the only security model supported by this
      library, it's also, so far as I know, the only security model defined for
      SNMPv3. The library is designed to be flexibile, so it could theoretically
      support other models, but for sake of clarity and simplicity, this class
      documentation assumes you are using the User-Based Security Model (USM).

   .. method:: usm.addUser( \
        userName, \
        authProtocol=None, \
        authSecret=None, \
        privProtocol=None, \
        privSecret=None, \
        secret=b"", \
        default=False, \
        defaultSecurityLevel=None, \
        namespace="", \
      )

      This method is used to input the security configuration of each user. As
      used here, the phrase "security configuration" refers to a unique
      combination of user name, authentication algorithm, privacy algorithm,
      authentication password, and privacy password. The :class:`Engine` needs
      this information before it can send or receive any SNMPv3 messages, so
      this should be the first method call made with a new :class:`Engine`
      object. Despite the large number of parameters, its behavior is mostly
      straightforward.

      The only required parameter is the `userName`. Other parameters depend on
      the level of security that the user supports. If the user supports
      authentication, then the `authProtocol` parameter expects a class that
      implements the authentication algorithm. Similarly, the `privProtocol`
      parameter specifies a privacy algorithm. Implementations of standard
      algorithms are provided in the :mod:`snmp.security.usm.auth` and
      :mod:`snmp.security.usm.priv` modules. It is also possible to write your
      own implementions by sub-classing :class:`snmp.security.usm.AuthProtocol`
      and :class:`snmp.security.usm.PrivProtocol`, respectively.

      The `authSecret` and `privSecret` parameters specify the authentication
      and privacy passwords.  Alternatively, if authentication and privacy use
      the same password, then the `secret` parameter may be used in lieu of the
      other two.

      Normally, a user will default to the highest security level that its
      configuration supports. If you desire a lower security level as the
      default for a particular user, specify the desired default with the
      `defaultSecurityLevel` parameter.

      The `namespace` parameter is only necessary if the :class:`Engine` has
      multiple security configurations under the same `userName`. This would
      mean that two remote engines have different algorithms or passwords for
      one user. In this case, you, as the administrator will need to organize
      the security configurations under different namespaces so that you can
      refer to them unambiguously.

      The purpose of namespaces is not actually to organize the security
      configurations, it's to organize the managed nodes (i.e. remote engines)
      in the network. A namespace should consist of all nodes that share the
      same security configurations. In a network containing only one namespace,
      you can ignore the concept of namespaces, and everything will belong to
      the default ``""`` namespace. Otherwise, you will need to pick names for
      each of your namespaces, and use those names both when adding security
      configurations, using this method, and when creating Managers, using the
      :meth:`Engine.Manager` factory method. Namespaces may use any string.

      (Ignore the words in parentheses if not using namespaces). Normally, the
      first user added (to a namespace) becomes the "default" user (for that
      namespace). To manually designate a user to be the default (for its
      namespace), give a value of ``True`` for the `default` parameter when
      adding that user.

   .. method:: shutdown

      This method closes network resources and terminates background threads. It
      is called automatically by the :meth:`__exit__` method when the
      :class:`Engine` is used within a context manager.

   .. method:: Manager( \
         address, \
         version=None, \
         domain=None, \
         localAddress=None, \
         autowait=None, \
         ** kwargs, \
      )

      This is a `Factory Method`_ for creating ``Manager`` objects. Each
      ``Manager`` object is responsible for a single remote engine, and expects
      to have exclusive responsibility for that engine (meaning you should
      create exactly one ``Manager`` for each remote engine). Note that, while
      all accesses to an :class:`Engine` should occur on a single thread, and
      each ``Manager`` should also be accessed within a single thread, it is
      allowable to create multiple threads, each with exclusive access to one or
      more ``Manager``\s.

      Provide the `address` parameter with the address of the remote host that
      this object will manage. The precise format depends on the `domain`. For
      UDP over IPv4, it expects a :class:`str` containing the IP address. If
      the remote engine is listening on a non-standard port, this parameter also
      accepts a tuple containing both the IP address and the port number.

      Similarly, the `localAddress` parameter allows you to select the IP
      address and port that the ``Manager`` will use to send and receive
      messages.

      The `autowait` parameter assigns a default value for the `wait` parameter
      to the ``Manager``'s request methods. If not given, its value falls back
      on the `autowait` argument provided in the :class:`Engine` constructor.
      See the :doc:`manager` page for an explanation of the `wait` parameter.

      `address` and `version` are the only positional parameters. All other
      arguments should be passed by keyword, as their ordering is subject to
      change in future library versions. The set of available keyword parameters
      depends on the SNMP version. See the duplicate method definitions below
      for details on version-specific parameters. The `version` parameter
      defaults to the :class:`Engine`'s `defaultVersion`.

   .. method:: Manager(address, version=SNMPv3, domain=None, \
      localAddress=None, autowait=None, engineID=None, securityModel=None, \
      defaultSecurityLevel=None, defaultUserName=None, namespace="")
      :noindex:

      .. note::

         Before creating a ``Manager``, you must add at least one user by
         calling ``Engine.usm.addUser()`` (see
         :meth:`snmp.security.usm.UsmAdmin.addUser`).

      The `engineID` parameter allows you to manually provide the engine ID of
      the managed engine. As this can be discovered automatically, there is
      almost no reason to do this. There's not even a performance advantage. The
      only reason to use it is if you are NOT using authentication, in which
      case there is a possibility that an attacker could inject an incorrect
      engine ID during discovery. Without authentication, the ``Manager`` will
      not be able to detect or correct the error, and so all your requests will
      time out. However, the solution is not to manually specify engineIDs. If
      you are concerned about attackers, and your network supports SNMPv3, then
      the answer is simply to use authentication. However, the parameter is
      provided, and you are free to use it.

      The `securityModel` parameter would allow you to choose a different
      security model if one existed. Since that's not the case, it's totally
      useless.

      `defaultUserName` and `defaultSecurityLevel` set the default user name and
      security level for the ``Manager``, overriding the namespace's default
      user, and the user's default security level (see
      :meth:`snmp.security.usm.UsmAdmin.addUser`).

      `namespace` selects the namespace for this ``Manager``. If you didn't use
      the `namespace` parameter when you called ``Engine.usm.addUser()``, then
      you don't need it here.

   .. method:: Manager(address, version=SNMPv2c, domain=None, \
      localAddress=None, autowait=None, community=None)
      :noindex:

      The `community` parameter sets the default community for this ``Manager``.
      This can also be configured at the :class:`Engine` level, with the
      `defaultCommunity` parameter to the constructor. Note that these
      parameters expect ``bytes`` objects, not ``str``\s.

   .. method:: Manager(address, version=SNMPv1, domain=None, \
      localAddress=None, autowait=None, community=None)
      :noindex:

      `community` behaves just as described under the ``SNMPv2c`` signature.

.. data:: SNMPv1
.. data:: SNMPv2c
.. data:: SNMPv3

   These enumerated values represent SNMP protocol versions in any method that
   accepts a `version` parameter. Their numerical values match those used in the
   `msgVersion` field of an SNMP message.

.. data:: noAuthNoPriv
   :canonical: snmp.security.levels.noAuthNoPriv

.. data:: authNoPriv
   :canonical: snmp.security.levels.authNoPriv

.. data:: authPriv
   :canonical: snmp.security.levels.authPriv

   These objects represent the three possible security levels in SNMP version 3.

.. toctree::
   :hidden:

   manager
   datatypes

.. _Facade: https://en.wikipedia.org/wiki/Facade_pattern
.. _Factory Method: https://en.wikipedia.org/wiki/Factory_method_pattern
