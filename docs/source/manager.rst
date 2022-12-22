Management Operations
=====================

All management operations require a Manager object, which is created using the :meth:`snmp.Engine.Manager` factory method.

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
