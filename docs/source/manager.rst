The Manager Interface
=====================

.. note::

   The classes described in this section do not correspond to specific class implementations. Instead, they describe the abstract interfaces of the various Manager objects returned by the :meth:`Engine.Manager()<snmp.Engine.Manager>` factory method.

.. py:class:: SnmpManager

   This class describes the common interface of both the :class:`SNMPv3Manager` and the :class:`SNMPv2cManager`. Application code using this interface should not need to differentiate between SNMPv3 and SNMPv2c machines. The :class:`SNMPv1Manager` conforms to the same interface (with the exception of the :meth:`getBulk` method), but requires additional application code to properly handle :data:`NoSuchName<snmp.NoSuchName>` errors, which are not used in SNMPv2c or SNMPv3.

   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
      )

      Send an SNMP Get request containing the provided list of OIDs.

      Each item in the `oids` argument list may be either an :class:`snmp.smi.OID`, or a string containing the representation of the OID (e.g. ``"1.3.6.1.2.1.1.1.0"``, or ``".1.3.6.1.2.1.1.1.0"``).

      Non-Blocking Requests
      *********************

      The default behavior (:ref:`asterisk<wait-default-warning>`) for this method is to block until a response is received, and then return the contents of the response in a :class:`snmp.smi.VarBindList`. However, when called with ``wait=False``, it will not wait for a response, and instead return a :class:`RequestHandle` corresponding to the request. You can then call the :meth:`RequestHandle.wait` method to await the response and retrieve its contents. For illustration, here are two equivalent ways to make a Get request and await the response:

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

      Since SNMP operates on an "unreliable" transport (UDP), there is always a possibility of messages getting lost in transit. It is also possible that the agent at that address is down, or doesn't even exist. While waiting for a response, the Manager (or the RequestHandle) will re-send the request every `requestPeriod` seconds. If it does not receive a response within `timeout` seconds, it will give up and raise a :class:`Timeout<snmp.Timeout>` exception.

      Be aware that the :class:`Engine<snmp.Engine>` uses a cooperative multitasking strategy, rather than a preemptive strategy, to maintain many requests at once. It can re-send a request even while waiting for a response to a different request (including requests belonging to other Managers, so long as they were created by the same Engine), but it will not preempt your application code. This means that in the following example, the Manager will only ever send the request once.

      .. code-block:: python

         handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=0.5, timeout=2.5, wait=False)
         time.sleep(3.0)
         vblist = handle.wait()

      The `refreshPeriod` is always measured from the time of the most recent message. The `timeout` is measured from the time that the request is made, and not from the time at which you call ``wait()``. In this next example, if the request is made at time 0.0s, and if there is no response, then the request will be re-sent at time 1.5s, and 2.5s, and then raise a :class:`Timeout<snmp.Timeout>` at 3.0s.

      .. code-block:: python

         handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1.0, timeout=3.0, wait=False)
         time.sleep(1.5)
         vblist = handle.wait()


      Finally, in this example, the request will time out before it ever considers re-sending.

      .. code-block:: python

         handle = manager.get("1.3.6.1.2.1.1.1.0", refreshPeriod=1.5, timeout=1.0, wait=False)
         vblist = handle.wait()

      Exceptions
      **********

      This method (or the ``wait()`` method of a corresponding :class:`RequestHandle`) raises the following exceptions:

      class:`snmp.Timeout`: No response within `timeout` seconds (more details above).

      :class:`snmp.ErrorResponse`: Indicates a nonzero error-status in the ResponsePDU.

      :class:`snmp.NoSuchName`: A sub-type of :class:`snmp.ErrorResponse`, this exception indicates an error-status of ``noSuchName``. Unlike other error-status values, ``noSuchName`` sometimes comes up in normal operation in SNMPv1, so it is convenient to be able to handle it in a separate ``except`` block from the more general :class:`snmp.ErrorResponse` type.

      :class:`snmp.ImproperResponse`: In order to guarantee that the returned :class:`VarBindList<snmp.smi.VarBindList>` contains the expected variables in the expected order, the Manager checks the variables in the response against the OIDs in the original request. If there is any discrepancy, it will raise an :class:`ImproperResponse<snmp.ImproperResponse>` exception, with the ``VarBindList`` stored in the ``variableBindings`` attribute.

      `Exception`_: In some cases, this method may raise an exception that is meant to get the attention of a human, rather than being handled automatically. These exceptions often relate to incorrect SNMPv3 security credentials, but not always. If crashes are unacceptable in your application, then you can catch all these exceptions with a generic ``except Exception`` block. This block should log or otherwise report to a human, any exceptions it catches, along with some identifying information for the remote agent you were trying to communicate with.

   .. py:method:: getBulk( \
         *oids, \
         nonRepeaters = 0, \
         maxRepetitions = 1, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
      )

      Send an SNMP GetBulk request containing the provided list of OIDs.

      Aside from the addition of the `nonRepeaters` and `maxRepetitions` parameters, the usage and behavior of this method is exactly the same as the :meth:`get` method.

      Multiple GetNext Requests In One
      ********************************

      The GetBulk request is essentially an enhanced version of the GetNext request. With the `maxRepetitions` argument, you can request the results of several successive GetNext requests, combined into a single response. For example, this code snippet requests the ``ifDescr``, ``ifType``, and ``ifOperStatus`` for the first two rows in the remote machine's ``ifTable``.

      .. code-block:: python

         vblist = manager.getBulk(ifDescr, ifType, ifOperStatus, maxRepetitions=2)
         print(vblist)

      Here is the output of the response I got from my printer:

      .. code-block:: shell

         1.3.6.1.2.1.2.2.1.2.1: OctetString(b'NC-8200h')
         1.3.6.1.2.1.2.2.1.3.1: Integer32(7)
         1.3.6.1.2.1.2.2.1.8.1: Integer32(1)
         1.3.6.1.2.1.2.2.1.2.2: OctetString(b'SoftwareLoopBack')
         1.3.6.1.2.1.2.2.1.3.2: Integer32(24)
         1.3.6.1.2.1.2.2.1.8.2: Integer32(1)

      This response contains two "repetitions" of the query. The first three variables show that ``"NC-2800h"`` is an ``iso88023Csmacd(7)`` interface, which is currently ``up(1)`` (the ``ifType`` an ``ifOperStatus`` values are enumerated in ``IANAifType-MIB`` and ``IF-MIB``, respectively). The next three variables would be found in the response to a GetNext request that used the OIDs of the first three variables. They tell of a ``"SoftwareLoopBack"`` interface of type ``softwareLoopback(24)`` which is currently ``up(1)`` as well.

      A successful response is required, according to the protocol, to contain at least one repetition (unless `maxRepetitions` is zero). It should contain the full number of repetitions, if possible, but it is not guaranteed. This method additionally guarantees that the returned :class:`VarBindList<snmp.smi.VarBindList>` will not contain any partial repetitions (i.e. if three OIDs are requested, the number of variables in the response will be a multiple of three). If a response does not meet this guarantee, it will raise an :class:`ImproperResponse<snmp.ImproperResponse>` exception. In this case, the :class:`VarBindList<snmp.smi.VarBindList>` is still available via the exception object's ``variableBindings`` attribute.

      Non-Repeated OIDs
      *****************

      It is also possible to request individual scalar values as part of a GetBulk request. When the `nonRepeaters` is non-zero, then the first `nonRepeaters` OIDs in the request are excluded from the repetition.

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
      )

      Send an SNMP GetNext request containing the provided list of OIDs.

      The usage and behavior of this method is exactly the same as the :meth:`get` method.

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
      )

      Send an SNMP Set request containing the provided list of VarBinds.

      Each item in the `varbinds` argument list may be either a :class:`snmp.smi.VarBind`, or a tuple containing first the OID (either as an :class:`snmp.smi.OID`, or as a string) and then the requested value for the variable.

      Aside from the `varbinds` argument, the usage and behavior of this method is exactly the same as the :meth:`get` method.

.. py:class:: SNMPv3Manager

   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         user = None, \
         securityLevel = None, \
         context = b"", \
      )

      This method extends :meth:`SnmpManager.get` with some SNMPv3-specific parameters.

      As explained in the :meth:`snmp.Engine.Manager` section, each SNMPv3 Manager object is configured with a default user and security level. You can override these defaults for a particular request using the `user` and `securityLevel` parameters. The `user` must be a ``str``, and the `securityLevel` must be one of the following: :data:`snmp.noAuthNoPriv`, :data:`snmp.authNoPriv`, or :data:`snmp.authPriv`. Remember that before you can make an ``authNoPriv`` or ``authPriv`` request, you must configure the authentication and privacy protocol(s) and password(s) for the user by calling :meth:`Engine.addUser()<snmp.Engine.addUser>`.

      You can probably ignore the `context` argument, but if you do need it, then I'm sure I don't have to explain it. The default `context` is not configurable, mostly because I'm not sure anyone even uses it. If you would like that changed, feel free to file a GitHub issue or email me about it.

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
      )

      See :meth:`SnmpManager.getBulk` and :meth:`get`.

   .. py:method:: getNext( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         user = None, \
         securityLevel = None, \
         context = b"", \
      )

      See :meth:`SnmpManager.getNext` and :meth:`get`.

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         user = None, \
         securityLevel = None, \
         context = b"", \
      )

      See :meth:`SnmpManager.set` and :meth:`get`.

.. py:class:: SNMPv2cManager

   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

   .. py:method:: getBulk( \
         *oids, \
         nonRepeaters = 0, \
         maxRepetitions = 1, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

   .. py:method:: getNext( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

.. py:class:: SNMPv1Manager

   .. py:method:: get( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

   .. py:method:: getBulk( \
         *oids, \
         nonRepeaters = 0, \
         maxRepetitions = 1, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

   .. py:method:: getNext( \
         *oids, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

   .. py:method:: set( \
         *varbinds, \
         timeout = 10.0, \
         refreshPeriod = 1.0, \
         wait = None, \
         community = None, \
      )

SNMP defines four management operations: Get, Get-Next, Get-Bulk (since v2c),
and Set. With this library, management operations require a Manager object,
which is created using the :meth:`snmp.Engine.Manager` factory method. The
concrete classes and method signatures are outlined below, but the parameters
are explained here, as they are nearly identical for all methods.

The variable-length `oids` parameter to the ``get*()`` methods specifies the
objects to be queried. Each OID may either be an :class:`snmp.smi.OID` object,
or a string containing a dot-sepearated OID representation (e.g.
``"1.3.6.1.2.1.1.1.0"``). The ``get()`` method performs a Get request, which
requests the value for each queried object. The ``getNext()`` method performs a
Get-Next request, which requests the next valid object, according to the
ordering of the objects' OIDs. The ``getBulk()`` method performs a Get-Bulk
request, which requests the object referenced by each OID, as well as the next
(`maxRepetitions` - 1) objects for all but the first `nonRepeaters` OIDs. For a
more complete, though no less confusing, explanation of Get-Bulk, see
:rfc:`3416#section-4.2.3`.

The ``set()`` method uses a similar variable-length parameter called
`varbinds`. As the name suggests, this parameter expects
:class:`snmp.pdu.VarBind` objects. This method performs an SNMP Set operation,
which requests that the remote engine assign ``varbind.value`` to the object
with OID ``varbind.name``.

The `securityLevel` parameter (SNMPv3 only) may be used to select the security
level of an individual request. The default security level is configured in the
call to :meth:`snmp.Engine.Manager`, so this parameter should only be needed in
rare cases. Similarly, you may manually specify the user for an individual
request with the ``user`` parameter.

The `community` parameter (SNMPv1 and SNMPv2c only) specifies the community
for an individual request. The default community is configurable both in the
call to :meth:`snmp.Engine.Manager`, and in the :class:`Engine` constructor, so
this parameter should only be needed in rare cases. Note that this parameter
expects a ``bytes`` object, not a ``str``.

The `wait` parameter determines the control flow after the request has been
sent. If `wait` is ``True`` (the default), then the method will block until a
response arrives. When the response _does_ arrive, the method will either return
a :class:`snmp.pdu.VarBindList`, or raise an :class:`snmp.pdu.ErrorResponse`.
This blocking approach limits an application to a single outstanding request at
a time. In the case that `wait` is ``False``, the method will immediately return
a "request handle". When your application is ready to process the response, call
the handle's ``wait()`` method, which will block until the response arrives, and
then return or raise, as alredy described. Note that this means that the line
``response = manager.get(oid, wait=True)`` behaves identically to the line
``response = manager.get(oid, wait=False).wait()``. The default value for `wait`
is configurable with the `autowait` parameter to both the
:meth:`snmp.Engine.Manager` method and the :class:`snmp.Engine` constructor.

The `timeout` parameter gives the maximum amount of time (in seconds) that a
request should wait for a response before raising a
:class:`snmp.manager.Timeout` exception. The `refreshPeriod` parameter
configures how often to retry (resend) an unanswered request.

.. note::

   In some cases, the remote engine may respond with a ReportPDU indicating why
   it is unable to provide an answer to a request, such as if the authentication
   check fails. If this ReportPDU is sent with a lower level of security than
   the request, then it will not cause the request (or the ``wait()`` method) to
   return right away, as this would open an avenue for a denial-of-service
   attack. When the request expires, it will raise an exception that indicates
   the reported error, instead of the usual :class:`snmp.manager.Timeout`.

Manager Interface
-----------------

A Manager object represents a relationship with a single remote Agent. The transport configuration is stored internally, so that you do not need to specify the IP address for each request. An application that manages multiple nodes will use multiple Manager objects.

The interface varies slightly between SNMP versions, but the design is essentially the same. Each request method generates a request handle. The wait() method of that handle blocks until a response is received, or until the timeout expires. In the default case, the request method will call wait() internally, and return the resulting VarBindList (assuming the request is successful). However, the wait parameter gives the caller the option to return the handle immediately after the request has been sent. This allows an application to send multiple requests at once, rather than automatically awaiting the response to each request before sending the next one.

.. py:class:: SNMPv3Manager
   :noindex:

   If the response indicates an error, the call will raise an
   :class:`ErrorResponse<snmp.ErrorResponse>` exception. If the error-status is
   ``noSuchName``, the error will be an instance of
   :class:`NoSuchName<snmp.NoSuchName>`, which is a subclass of
   :class:`ErrorResponse<snmp.ErrorResponse>`.

   If the variables in the response do not match up correctly with the OIDs in
   the request, then the call will raise an
   :class:`ImproperResponse<snmp.ImproperResponse>` exception. A corollary
   to this requirement is that that the caller can trust that a
   :class:`VarBindList<snmp.smi.VarBindList>` returned by one of these request
   methods will always have the expected number of entries, in the correct
   order.

   Finally, an unanswered request will eventually result in a
   :class:`Timeout<snmp.Timeout>`.

   For completeness, there is one last type of exception that can be thrown, but
   only to indicate a problem that requires manual intervention (e.g. the
   security credentials are invalid). This type of exception should usually be
   allowed to propagate to the highest level, so that a human can fix the code.
   However, if you must absolutely eliminate all possibility of an exception
   breaking through, then you should use ``except Exception``.

   .. py:method:: get([ \
         oid(s), ..., \
         userName=None, \
         securityLevel=None, \
         context=b"", \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])
      :noindex:

   .. py:method:: getBulk([ \
         oid(s), ..., \
         nonRepeaters=0, \
         maxRepetitions=1, \
         userName=None, \
         securityLevel=None, \
         context=b"", \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])
      :noindex:

   .. py:method:: getNext([ \
         oid(s), ..., \
         userName=None, \
         securityLevel=None, \
         context=b"", \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])
      :noindex:

   .. py:method:: set([ \
         varbind1, varbind2, ..., \
         userName=None, \
         securityLevel=None, \
         context=b"", \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])
      :noindex:

.. py:class:: SNMPv2cManager

   .. py:method:: get([ \
         oid(s), ..., \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

   .. py:method:: getBulk([ \
         oid(s), ..., \
         nonRepeaters=0, \
         maxRepetitions=1, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

   .. py:method:: getNext([ \
         oid(s), ..., \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

   .. py:method:: set([ \
         varbind1, varbind2, ..., \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

.. py:class:: SNMPv1Manager

   .. py:method:: get([ \
         oid(s), ..., \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

   .. py:method:: getNext([ \
         oid(s), ..., \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

   .. py:method:: set([ \
         varbind1, varbind2, ..., \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

.. py:class:: RequestHandle

   .. py:method:: wait()
      raise ErrorResponse
      raise ImproperResponse
      - variableBindings
      raise NoSuchName (SNMPv1)
      raise Timeout

.. _Exception: https://docs.python.org/3/library/exceptions.html#Exception
