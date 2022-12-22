Management Operations
=====================

SNMP defines four management operations: Get, Get-Next, Get-Bulk (since v2c),
and Set. With this library, management operations require a Manager object,
which is created using the :meth:`snmp.Engine.Manager` factory method. The
concrete classes and method signatures are outlined below, but the parameters
are explained here, as they are nearly identical for all methods.

The variable-length ``oids`` parameter to the ``get*()`` methods specifies the
objects to be queried. Each OID may either be an :class:`snmp.types.OID` object,
or a string containing a dot-sepearated OID representation (e.g.
"1.3.6.1.2.1.1.1.0"). The ``get()`` method performs a Get request, which
requests the value for each queried object. The ``getNext()`` method performs a
Get-Next request, which requests the next valid object, according to the
ordering of the objects' OIDs. The ``getBulk()`` method performs a Get-Bulk
request, which requests the object referenced by each OID, as well as the next
(`maxRepetitions` - 1) objects for all but the first `nonRepeaters` OIDs. For a
more complete, though no less confusing, explanation of Get-Bulk, see
:rfc:`3416#section-4.2.3`.

The ``set()`` method uses a similar variable-length parameter called
``varbinds``. As the name suggests, this parameter expects
:class:`snmp.types.VarBind` objects. This method performs an SNMP Set operation,
which requests that the remote engine assign ``varbind.value`` to the object
with OID ``varbind.name``.

.. class:: SNMPv3UsmManager

   .. method:: get( \
         * oids, \
         securityLevel=None, \
         user=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: getBulk( \
         * oids, \
         nonRepeaters=0, \
         maxRepetitions=0, \
         securityLevel=None, \
         user=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: getNext( \
         * oids, \
         securityLevel=None, \
         user=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: set(* varbinds, \
         securityLevel=None, \
         user=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

.. class:: SNMPv2cManager

   .. method:: get( \
         * oids, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: getBulk( \
         * oids, \
         nonRepeaters=0, \
         maxRepetitions=0, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: getNext( \
         * oids, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: set( \
         * varbinds, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

.. class:: SNMPv1Manager

   .. method:: get( \
         * oids, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: getNext( \
         * oids, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )

   .. method:: set( \
         * varbinds, \
         community=None, \
         wait=None, \
         timeout=10.0, \
         refreshPeriod=1.0, \
      )
