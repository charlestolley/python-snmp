Exceptions
----------

.. module:: snmp
   :noindex:

.. py:class:: ErrorStatus

   This class enumerates the possible error-status values of a PDU. These names correspond to the definitions in `RFC 3416, Section 3`_\ .

   .. data:: noError

   .. data:: tooBig

   .. data:: noSuchName

   .. data:: badValue

   .. data:: readOnly

   .. data:: genErr

   .. data:: noAccess

   .. data:: wrongType

   .. data:: wrongLength

   .. data:: wrongEncoding

   .. data:: wrongValue

   .. data:: noCreation

   .. data:: inconsistentValue

   .. data:: resourceUnavailable

   .. data:: commitFailed

   .. data:: undoFailed

   .. data:: authorizationError

   .. data:: notWritable

   .. data:: inconsistentName

.. py:exception:: ErrorResponse

   This exception type indicates a non-zero error-status in a Response-PDU.

   .. property:: status
      :type: ErrorStatus

      The error-status from the Response-PDU.

   .. property:: index
      :type: int

      The error-index from the Response-PDU.

      The value of this attribute is guaranteed to be between zero and the
      length of the ``variableBindings`` (inclusive), even if the value from
      the Response-PDU is (illegally) outside of that range.

   .. property:: variableBindings
      :type: VarBindList

      The :class:`VarBindList<snmp.smi.VarBindList>` from the Response-PDU.

.. py:exception:: NoSuchName(ErrorResponse)

   A special case of :class:`ErrorResponse` to make it easy for an SNMPv1 application to handle ``noSuchName`` responses. Whereas most error-status values indicate an exception, SNMPv1 uses ``noSuchName`` as part of normal operation. In order to handle the two types separately, the ``except NoSuchName`` block must come first.

   .. code-block:: python

      from snmp import *

      engine = Engine(SNMPv1)
      manager = engine.Manager("127.0.0.1")

      try:
          vblist = manager.getNext("1.3.7")
      except NoSuchName as err:
          if err.index > 0:
              vb = err.variableBindings[err.index-1]
              print(f"noSuchName: {vb.name}")
          else:
              print("Caught NoSuchName")
      except ErrorResponse as err:
          print(f"Error: {err.status.name}")
      else:
          print(vblist)

   .. property:: status
      :type: ErrorStatus

      This value will always be :data:`ErrorStatus.noSuchName`.

   .. property:: index
      :type: int

      See :data:`ErrorResponse.index`

   .. property:: variableBindings
      :type: VarBindList

      See :data:`ErrorResponse.variableBindings`

.. py:exception:: Timeout

   This exception type indicates that a request has expired without a valid
   response.

.. py:exception:: ImproperResponse

   This exception type indicates that the variable-bindings of a Response-PDU
   do not constitute a valid response to the request. For example, if a Get
   request contains two OIDs, and the Response-PDU returns the two variables
   in the wrong order, then the :meth:`SnmpManager.get` method (or the
   :meth:`RequestHandle.wait` method) will raise this error.

   .. property:: variableBindings
      :type: VarBindList

      The list of variable bindings from the Response-PDU.

.. _RFC 3416, Section 3: https://datatracker.ietf.org/doc/html/rfc3416.html#section-3
