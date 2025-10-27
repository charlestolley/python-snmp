The Manager Interface
=====================

.. note::

   The classes described in this section do not correspond to specific class implementations. Instead, they describe the abstract interfaces of the various Manager objects returned by the :meth:`Engine.Manager()<snmp.Engine.Manager>` factory method.

.. py:class:: SnmpManager

   This class describes the common interface for :class:`SNMPv3Manager`, :class:`SNMPv2cManager`, and :class:`SNMPv1Manager` objects. Each Manager object is pre-configured to communicate with a specific remote machine (see the :meth:`Engine.Manager()<snmp.Engine.Manager>` `address` parameter). Code written for this interface should not need to differentiate between SNMPv3 and SNMPv2c machines. SNMPv1 machines will behave almost the same, but where an SNMPv2c or SNMPv3 response would contain a :class:`NoSuchObject<snmp.smi.NoSuchObject>`, :class:`NoSuchInstance<snmp.smi.NoSuchInstance>`, or :class:`EndOfMibView<snmp.smi.EndOfMibView>` object, an SNMPv1 response will simply have an error-status of ``noSuchName``, triggering a :class:`NoSuchName<snmp.NoSuchName>` exception. An application wishing to support all three protocols must properly handle both of these cases.


   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      Send an SNMP Get request containing the provided list of OIDs.

      Each item in the `oids` argument list may be either an :class:`snmp.smi.OID`, or a string containing the representation of the OID (e.g. ``"1.3.6.1.2.1.1.1.0"``, or ``".1.3.6.1.2.1.1.1.0"``).

      Non-Blocking Requests
      *********************

      The default behavior (:ref:`asterisk<wait-default-warning>`) for this method is to block until a response is received, and then return the contents of the response in a :class:`VarBindList<snmp.smi.VarBindList>`. However, when called with ``wait=False``, it will not wait for a response, and instead return a :class:`RequestHandle` corresponding to the request. You can then call the :meth:`RequestHandle.wait` method to await the response and retrieve its contents. For illustration, here are two equivalent ways to make a Get request and await the response:

      .. code-block:: python

         vblist = manager.get("1.3.6.1.2.1.1.1.0", wait=True)
         vblist = manager.get("1.3.6.1.2.1.1.1.0", wait=False).wait()

      This feature makes it possible to send requests to several machines in parallel

      .. code-block:: python

         handle1 = manager1.get("1.3.6.1.2.1.1.1.0", wait=False)
         handle2 = manager2.get("1.3.6.1.2.1.1.1.0", wait=False)
         handle3 = manager3.get("1.3.6.1.2.1.1.1.0", wait=False)

         vblist1 = handle1.wait()
         vblist2 = handle2.wait()
         vblist3 = handle3.wait()

      rather than one after another.

      .. code-block:: python

         vblist1 = manager1.get("1.3.6.1.2.1.1.1.0", wait=True)
         vblist2 = manager2.get("1.3.6.1.2.1.1.1.0", wait=True)
         vblist3 = manager3.get("1.3.6.1.2.1.1.1.0", wait=True)

      In the first case, all three requests are sent at the same time, allowing the remote agents to process and respond to them in parallel. The second case is about three times slower, because each request is sent only after the manager receives the response to the previous request.

      .. _wait-default-warning:

      .. warning::

         The default argument for `wait` is actually not ``True``, it's ``None``. ``True`` is the default in the sense that it's the default for the `autowait` parameter to the :class:`Engine()<snmp.Engine>` constructor, which sets the default for the `autowait` parameter to the :class:`Engine.Manager()<snmp.Engine.Manager>` method. However, a Manager created with ``autowait=False`` will use the ``wait=False`` behavior by default.

      No Response?
      ************

      Since SNMP operates on an "unreliable" transport (UDP), there is always a possibility of messages getting lost in transit. It is also possible that the machine, or the agent that should be running on the machine, is down, or doesn't even exist. While waiting for a response, the Manager (or the RequestHandle) will re-send the request every `refreshPeriod` seconds. If it does not receive a response within `timeout` seconds, it will give up and raise a :class:`Timeout<snmp.Timeout>` exception.

      Be aware that the :class:`Engine<snmp.Engine>` uses a cooperative multitasking strategy, rather than a preemptive strategy, to maintain many requests at once. It can re-send a request even while waiting for a response to a different request (including requests belonging to other Managers, so long as they were created by the same Engine), but it will not preempt your application code. This means that in the following example, the Manager will only ever send the request once.

      .. code-block:: python

         handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=0.5, timeout=2.5, wait=False)
         time.sleep(3.0)
         vblist = handle.wait()

      The `refreshPeriod` is always measured from the time of the most recent message. The `timeout` is measured from the time of the request, and not from the time at which you call ``wait()``. In this next example, if the request is made at time 0.0s, and if there is no response, then the request will be re-sent at time 1.5s, and 2.5s, and then raise a :class:`Timeout<snmp.Timeout>` at 3.0s.

      .. code-block:: python

         handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1.0, timeout=3.0, wait=False)
         time.sleep(1.5)
         vblist = handle.wait()


      Finally, in this example, the request will time out before it ever considers re-sending.

      .. code-block:: python

         vblist = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1.5, timeout=1.0, wait=True)

      Exceptions
      **********

      This method (or the ``wait()`` method of a corresponding :class:`RequestHandle`) raises the following exceptions:

      :class:`snmp.Timeout`: No response within `timeout` seconds (more details above).

      :class:`snmp.ErrorResponse`: Indicates a nonzero error-status in the ResponsePDU.

      :class:`snmp.NoSuchName`: A sub-type of :class:`snmp.ErrorResponse`, this exception indicates an error-status of :data:`noSuchName<snmp.ErrorStatus.noSuchName>`. Unlike other error-status values, ``noSuchName`` sometimes comes up in the normal operation of SNMPv1, so it is convenient to be able to handle it in a separate ``except`` block from the more general :class:`snmp.ErrorResponse` type.

      :class:`snmp.ImproperResponse`: In order to guarantee that the returned :class:`VarBindList<snmp.smi.VarBindList>` contains the expected variables in the expected order, the Manager checks the variables in the response against the OIDs in the original request. If there is any discrepancy, it will raise an :class:`ImproperResponse<snmp.ImproperResponse>` exception, which will still give you access to the ``VarBindList`` via the :attr:`variableBindings<snmp.ImproperResponse.variableBindings>` attribute.

      `Exception`_: In some cases, this method may raise an exception that is meant to get the attention of a human, rather than being handled automatically. These exceptions often relate to incorrect SNMPv3 security credentials, but not always. If crashes are unacceptable in your application, then you can catch all these exceptions with a generic ``except Exception`` block. This block should log or otherwise report to a human, any exceptions it catches, along with some information to help identify which Manager object (and thereby which machine) the exception came from.

   .. py:method:: getBulk( \
         *oids, \
         nonRepeaters = 0, \
         maxRepetitions = 1, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      Send an SNMP GetBulk request containing the provided list of OIDs.

      Aside from the addition of the `nonRepeaters` and `maxRepetitions` parameters, the usage and behavior of this method is exactly the same as the :meth:`get` method.

      Multiple GetNext Requests In One
      ********************************

      The GetBulk request is essentially an enhanced version of the GetNext request. With the `maxRepetitions` argument, you can request the results of several successive GetNext requests, combined into a single response. For example, this code snippet requests the ``ifDescr``, ``ifType``, and ``ifOperStatus`` for the first two rows in a machine's ``ifTable``.

      .. code-block:: python

         vblist = manager.getBulk(ifDescr, ifType, ifOperStatus, maxRepetitions=2)
         print(vblist)

      Here is the response I got from my printer:

      .. code-block:: shell

         1.3.6.1.2.1.2.2.1.2.1: OctetString(b'NC-8200h')
         1.3.6.1.2.1.2.2.1.3.1: Integer32(7)
         1.3.6.1.2.1.2.2.1.8.1: Integer32(1)
         1.3.6.1.2.1.2.2.1.2.2: OctetString(b'SoftwareLoopBack')
         1.3.6.1.2.1.2.2.1.3.2: Integer32(24)
         1.3.6.1.2.1.2.2.1.8.2: Integer32(1)

      This response contains two "repetitions" of the query. The first three variables show that ``"NC-2800h"`` is an ``iso88023Csmacd(7)`` interface, which is currently ``up(1)`` (the ``ifType`` an ``ifOperStatus`` values are enumerated in ``IANAifType-MIB`` and ``IF-MIB``, respectively). The next three variables would be found in the response to a GetNext request that used the OIDs of the first three variables. They tell of a ``"SoftwareLoopBack"`` interface of type ``softwareLoopback(24)`` which is currently ``up(1)`` as well.

      A successful response is required, according to the protocol, to contain at least one repetition (unless `maxRepetitions` is zero). It should contain the full number of repetitions, if possible, but this is not guaranteed. This method additionally guarantees that the returned :class:`VarBindList<snmp.smi.VarBindList>` will not contain any partial repetitions (i.e. if three OIDs are requested, the number of variables in the response will be a multiple of three). If a response does not meet this guarantee, the call will raise an :class:`ImproperResponse<snmp.ImproperResponse>` exception. In this case, the :class:`VarBindList<snmp.smi.VarBindList>` is still available via the exception object's :attr:`variableBindings<snmp.ImproperResponse.variableBindings>` attribute.

      Non-Repeated OIDs
      *****************

      It is also possible to include single queries in the same GetBulk request as repeated queries. When the `nonRepeaters` is non-zero, then the first `nonRepeaters` OIDs in the request are excluded from the repetition.

      One way to use this feature might be to attach a timestamp to the data in the response, such as in this example.

      .. code-block:: python

         vblist = manager.getBulk(
            sysUpTime,
            ifDescr,
            ifInOctets,
            nonRepeaters=1,
            maxRepetitions=2,
         )
         print(vblist)

      As you can see, the response includes ``sysUpTime.0`` in the first slot, but the successor to this variable is not included in the second repetition of the query.

      .. code-block:: shell

         1.3.6.1.2.1.1.3.0: TimeTicks(95500355)
         1.3.6.1.2.1.2.2.1.2.1: OctetString(b'NC-8200h')
         1.3.6.1.2.1.2.2.1.10.1: Counter32(206469550)
         1.3.6.1.2.1.2.2.1.2.2: OctetString(b'SoftwareLoopBack')
         1.3.6.1.2.1.2.2.1.10.2: Counter32(64)

   .. py:method:: getNext( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      Send an SNMP GetNext request containing the provided list of OIDs.

      The usage and behavior of this method is exactly the same as the :meth:`get` method.

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      Send an SNMP Set request containing the provided list of VarBinds.

      Each item in the `varbinds` argument list may be either a :class:`snmp.smi.VarBind`, or a tuple containing first the OID (either as an :class:`snmp.smi.OID`, or as a string) and then the requested value for the variable, as an :mod:`snmp.smi` type.

      Aside from the `varbinds` argument, the usage and behavior of this method is exactly the same as the :meth:`get` method.

.. py:class:: RequestHandle

   .. py:method:: wait() -> snmp.smi.VarBindList

      See :meth:`SnmpManager.get`.

.. py:class:: RequestPoller

   Similar to the standard library `Polling Objects`_, a :class:`RequestPoller` can monitor several :class:`RequestHandle`\ s and tell you when they are ready to be :meth:`wait()<RequestHandle.wait>`\ ed on.

   Use the :meth:`Engine.poll()<snmp.Engine.poll>` method to create a :class:`RequestPoller` object.

   .. py:method:: register(handle: RequestHandle)

      Register a `handle` for monitoring by the :meth:`wait` method.

   .. py:method:: wait(timeout: float = None) -> List[RequestHandle]

      Return the list of handles that are ready, or block until one becomes ready.

      If a handle is "ready", then its :meth:`RequestHandle.wait` method will return immediately, or raise an exception.

      If `timeout` is not ``None``, and no handles become ready within `timeout` seconds, then the call will return an empty :class:`list`.

.. py:class:: SNMPv3Manager

   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         user = None, \
         securityLevel = None, \
         context = b"", \
      ) -> snmp.smi.VarBindList | RequestHandle

      This method extends :meth:`SnmpManager.get` with some SNMPv3-specific parameters.

      As explained in the :meth:`snmp.Engine.Manager` section, each SNMPv3 Manager object is configured with a default user and security level. You can override these defaults for a particular request using the `user` and `securityLevel` parameters. The `user` must be a ``str``, and the `securityLevel` must be one of the following: :data:`snmp.noAuthNoPriv`, :data:`snmp.authNoPriv`, or :data:`snmp.authPriv`. Remember that before you can make an ``authNoPriv`` or ``authPriv`` request, you must configure the authentication and privacy protocol(s) and password(s) for the user by calling :meth:`Engine.addUser()<snmp.Engine.addUser>`.

      The `context` argument is not worth explaining, because I'm not even sure anyone even uses it. The default `context` is not configurable for the same reason. If you do use it, and want the default to be configurable, feel free to file a GitHub issue or email me about it.

   .. py:method:: getBulk( \
         *oids, \
         nonRepeaters = 0, \
         maxRepetitions = 1, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         user = None, \
         securityLevel = None, \
         context = b"", \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.getBulk` and :meth:`get`.

   .. py:method:: getNext( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         user = None, \
         securityLevel = None, \
         context = b"", \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.getNext` and :meth:`get`.

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         user = None, \
         securityLevel = None, \
         context = b"", \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.set` and :meth:`get`.

.. py:class:: SNMPv2cManager

   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      This method extends :meth:`SnmpManager.get` by adding the `community` parameter.

      As explained in the :meth:`snmp.Engine.Manager` section, each SNMPv2c Manager object is configured with a default community name. The `community` parameter allows you to use a different community name for an individual request. The argument type is ``bytes`` (a ``str`` will not work)

   .. py:method:: getBulk( \
         *oids, \
         nonRepeaters = 0, \
         maxRepetitions = 1, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.getBulk` and :meth:`get`.

   .. py:method:: getNext( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.getNext` and :meth:`get`.

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.set` and :meth:`get`.

.. py:class:: SNMPv1Manager

   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      This method extends :meth:`SnmpManager.get` by adding the `community` parameter.

      As explained in the :meth:`snmp.Engine.Manager` section, each SNMPv1 Manager object is configured with a default community name. The `community` parameter allows you to use a different community name for an individual request. The argument type is ``bytes`` (a ``str`` will not work)

   .. py:method:: getBulk( \
         *oids, \
         nonRepeaters = 0, \
         maxRepetitions = 1, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      This method simulates a GetBulk request (which is not defined in SNMPv1) using a GetNext request. The response will never contain more than repetition for any OID in the request.

   .. py:method:: getNext( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.getNext` and :meth:`get`.

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      ) -> snmp.smi.VarBindList | RequestHandle

      See :meth:`SnmpManager.set` and :meth:`get`.

.. _Exception: https://docs.python.org/3/library/exceptions.html#Exception
.. _Polling Objects: https://docs.python.org/3/library/select.html#polling-objects
