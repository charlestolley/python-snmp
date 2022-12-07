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

      This module is still under development. It currently supports the
      "CommandGenerator" role, which allows the user to send requests and
      receive responses. Future versions will add support for sending and
      receiving notifications (i.e. traps), and for accepting incoming
      requests.

   While this reference does roughly follow a logical order, its top focus is on
   thoroughness or completeness. For a proper tutorial, see the
   :doc:`getting_started` page.

.. class:: Engine( \
      defaultVersion=SNMPv3, \
      defaultDomain=TransportDomain.UDP, \
      defaultSecurityModel=SecurityModel.USM, \
      defaultCommunity="", \
      autowait=True, \
   )

   Technically speaking, this class is a Facade_ for the various components in
   this library. Because it manages network resources and background threads, it
   is important to properly close it at the end of its life. The recommended way
   to do this is with a context manager (e.g. ``with Engine() as engine``). The
   alternative is to call :meth:`shutdown` directly at the end of the
   :class:`Engine`'s useful life. The latter approach is most useful for
   interactive settings, such as a Python interactive shell session.

   The arguments to the constructor configure the default argument values for
   the :meth:`Manager` factory method. `defaultVersion` is the only positional
   argument. All other arguments should be passed by keyword, as their ordering
   is subject to change in future library versions.

   .. property:: usm

      This property refers to a :class:`snmp.security.usm.UsmAdmin` object. It's
      public API contains only a single method called ``addUser()``, which you
      must call to tell the :class:`Engine` about users' security settings. See
      :meth:`snmp.security.usm.UsmAdmin.addUser` for details about that method.

   .. method:: shutdown

      This method closes network resources and terminates background threads. It
      is called automatically by the :meth:`__exit__` method when the
      :class:`Engine` is used within a context manager.

   .. method:: Manager( \
         address, \
         version=None, \
         domain=None, \
         autowait=None, \
         ** kwargs, \
      )

      This is a `Factory Method`_ for creating ``Manager`` objects. Each
      ``Manager`` object is responsible for a single remote engine, and expects
      to have exclusive responsibility for that engine (meaning you should
      create exactly one ``Manager`` for each remote engine).

      `address` and `version` are the only positional arguments. All other
      arguments should be passed by keyword, as their ordering is subject to
      change in future library versions. The set of available keyword arguments
      depends on the SNMP version. See the duplicate method definitions below
      for details on version-specific arguments. The `version` parameter
      defaults to the :class:`Engine`'s `defaultVersion`.

      The data type of `address` depends on the `domain`. For UDP over IPv4, it
      it expects a :class:`str` containing an IPv4 address. If the remote engine
      is listening on a non-standard port, this argument also accepts a 2-tuple,
      containing the IPv4 address and UDP port number.

      The `autowait` parameter assigns a default value for the `wait` parameter
      to the ``Manager``'s request methods. If not given, its value falls back
      on the `autowait` parameter provided in the :class:`Engine` constructor.
      Each request method causes a real SNMP request to be sent to the managed
      engine. The simplest programming model is simply to block until a response
      arrives, and then return the response. This is the behavior when `wait` is
      ``True`` (which is the default if you never touch the `wait` or `autowait`
      parmameters). However, this limits an application to a single outstanding
      request at a time. For larger systems, it may be more advantageous to send
      requests to multiple engines, or even multiple requests to a single
      engine, at the same time. When a request is made with ``wait=False``, the
      method will send the request, and then immediately return a "handle" for
      the request. This handle will have a public ``wait()`` method, which, when
      called, will block until the response arrives, and then return it, just as
      the request method would when `wait` was ``True``. Future library versions
      may explore enhancements to this, such as a "try-wait" feature, or some
      kind of request handle multiplexing (similar to the behavior of the POSIX
      :func:`select` function).

   .. method:: Manager(address, version=SNMPv3, domain=None, autowait=None, \
      engineID=None, securityModel=None, defaultSecurityLevel=None, \
      defaultUserName=None, namespace="")
      :noindex:

      .. note::

         User-Based security is not only the only security model supported by
         this library, it's also, so far as I know, the only security model
         defined for SNMPv3. The library is designed to be flexibile, so it
         could theoretically support other models, but for sake of clarity and
         simplicity, this section just assumes you are using the User-Based
         Security Model (USM).

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

   .. method:: Manager(address, version=SNMPv2c, domain=None, autowait=None, \
      community=None)
      :noindex:

      The `community` parameter sets the default community string for this
      ``Manager``. This can also be configured at the :class:`Engine` level,
      with the `defaultCommunity` argument to the constructor.

   .. method:: Manager(address, version=SNMPv1, domain=None, autowait=None, \
      community=None)
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

.. _Facade: https://en.wikipedia.org/wiki/Facade_pattern
.. _Factory Method: https://en.wikipedia.org/wiki/Factory_method_pattern
