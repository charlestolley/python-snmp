Management Operations
=====================

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

Manager Interface (Complete)
----------------------------

A Manager object represents a relationship with a single remote Agent. The transport configuration is stored internally, so that you do not need to specify the IP address for each request. An application that manages multiple nodes will use multiple Manager objects.

The interface varies slightly between SNMP versions, but the design is essentially the same. Each request method generates a request handle. The wait() method of that handle blocks until a response is received, or until the timeout expires. In the default case, the request method will call wait() internally, and return the resulting VarBindList (assuming the request is successful). However, the wait parameter gives the caller the option to return the handle immediately after the request has been sent. This allows an application to send multiple requests at once, rather than automatically awaiting the response to each request before sending the next one.

.. py:class:: SNMPv3Manager

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

   .. py:method:: getBulk([ \
         oid(s), ..., \
         nonRepeaters=0, \
         maxRepetitions=0, \
         userName=None, \
         securityLevel=None, \
         context=b"", \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

   .. py:method:: getNext([ \
         oid(s), ..., \
         userName=None, \
         securityLevel=None, \
         context=b"", \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

   .. py:method:: set([ \
         varbind1, varbind2, ..., \
         userName=None, \
         securityLevel=None, \
         context=b"", \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0 \
      ])

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
         maxRepetitions=0, \
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
