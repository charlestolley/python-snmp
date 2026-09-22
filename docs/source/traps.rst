Receiving Traps
===============

.. py:class:: SnmpTrapHandler

   This class describes an interface for you to write custom SNMP trap
   handlers. The :class:`SNMPv3TrapHandler` and :class:`SNMPv2cTrapHandler`
   classes define additional version-specific parameters. You can register your
   :class:`SnmpTrapHandler` by calling
   :meth:`Engine.setTrapHandler()<snmp.Engine.setTrapHandler>`.

   .. py:method:: trap(vblist, version, domain, address, **kwargs)

      The :class:`Engine<snmp.Engine>` calls this method every time it receives
      a trap (on the registered socket, and matching the registered SNMP
      version). It passes one positional argument containing the
      :class:`VarBindList<snmp.smi.VarBindList>`, and several additional
      keyword arguments, including `version`, `domain`, and `address`.

      The `version` argument gives the SNMP version of the trap message, which
      lets you know what additional keyword arguments to expect. The `domain`
      and `address` arguments contain the transport domain
      (:data:`UDP_IPv4<snmp.UDP_IPv4>` or :data:`UDP_IPv6<snmp.UDP_IPv6>`) and
      the source address from which the trap was sent.

.. py:class:: SNMPv3TrapHandler

   .. py:method:: trap( \
         vblist, \
         version, \
         domain, \
         address, \
         engineID, \
         namespaces, \
         user, \
         securityLevel, \
         context, \
         **kwargs \
      )

      This method extends :class:`SnmpTrapHandler.trap()` with some
      SNMPv3-specific parameters. You should always use `**kwargs`, as a future
      version of this interface may define additional keyword parameters.

      The `engineID` and `context` arguments contain the ``contextEngineID``
      and ``contextName`` of the SNMPv3 message.

      The `securityLevel` and `user` arguments tell you what level of security
      was applied to the trap message, and which user's credentials were used.

      The `namespaces` argument gives the :class:`set` of possible namespaces
      for the engine that sent the trap. If the `securityLevel` is
      :data:`noAuthNoPriv<snmp.noAuthNoPriv>`, this is simply the :class:`set`
      of all namespaces in which the `user` is defined. If the `securityLevel`
      is :data:`authNoPriv<snmp.authNoPriv>`, then `namespaces` contains only
      the namespaces for which that `user`'s credentials successfully verify
      the message digest. If the `securityLevel` is
      :data:`authPriv<snmp.authPriv>`, then the set contains only the
      namespaces for which the `user`'s credentials successfully verify the
      message digest *and* decrypt the message payload.

.. py:class:: SNMPv2cTrapHandler

   .. py:method:: trap(vblist, version, domain, address, community, **kwargs)

      This method extends :class:`SnmpTrapHandler.trap()` with the `community`
      parameter for SNMPv2c. You should always use `**kwargs`, as a future
      version of this interface may define additional keyword parameters.

.. py:class:: TrapListener

   The :class:`Engine<snmp.Engine>` provides this simple
   :class:`SnmpTrapHandler` implementation to make it very easy for users to
   get started with SNMP traps. To create a :class:`TrapListener` object, call
   :meth:`Engine.TrapListener()<snmp.Engine.TrapListener>`.

   .. py:method:: listen() -> tuple[VarBindList, dict]

      Wait for the :class:`Engine<snmp.Engine>` to receive a trap, and then
      return the :class:`VarBindList<snmp.smi.VarBindList>` and the
      :class:`dict` of keyword arguments that were passed to the
      :meth:`SnmpTrapHandler.trap` method.

.. py:class:: AsyncTrapListener

   An `async` version of :class:`TrapListener`.

   .. py:method:: listen() -> tuple[VarBindList, dict]
      :async:

      See :meth:`TrapListener.listen`.
