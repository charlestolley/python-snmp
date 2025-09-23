Dummy Title
===========

.. module:: snmp
   :noindex:

.. py:class:: ErrorStatus

   This class enumerates the possible (valid) values of the error-status field
   of a PDU. These names and values are defined by RFC 3416, Section 3.

   .. data:: noError = 0

   .. data:: tooBig = 1

   .. data:: noSuchName = 2

   .. data:: badValue = 3

   .. data:: readOnly = 4

   .. data:: genErr = 5

   .. data:: noAccess = 6

   .. data:: wrongType = 7

   .. data:: wrongLength = 8

   .. data:: wrongEncoding = 9

   .. data:: wrongValue = 10

   .. data:: noCreation = 11

   .. data:: inconsistentValue = 12

   .. data:: resourceUnavailable = 13

   .. data:: commitFailed = 14

   .. data:: undoFailed = 15

   .. data:: authorizationError = 16

   .. data:: notWritable = 17

   .. data:: inconsistentName = 18

.. py:exception:: ErrorResponse

   This exception type indicates a non-zero error-status in a Response-PDU.

   .. py:data:: status
      :type: ErrorStatus

      The error-status from the Response-PDU.

   .. py:data:: index
      :type: int

      The error-index from the Response-PDU.

      The value of this attribute is guaranteed to be between zero and the
      length of the ``variableBindings`` (inclusive), even if the value from
      the Response-PDU is outside of that range.

   .. py:data:: variableBindings
      :type: VarBindList

      The list of variable bindings from the Response-PDU.

.. py:exception:: NoSuchName(ErrorResponse)

   A special case of :class:`ErrorResponse` to make it easy for an SNMPv1
   application to handle ``noSuchName`` responses separately from other error
   statuses. Here is a simple example:

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

   .. py:data:: status
      :type: ErrorStatus

      See :data:`ErrorResponse.status`

   .. py:data:: index
      :type: int

      See :data:`ErrorResponse.index`

   .. py:data:: variableBindings
      :type: VarBindList

      See :data:`ErrorResponse.variableBindings`

.. py:exception:: Timeout

   This exception type indicates that a request has expired without a valid
   response.

.. py:exception:: ImproperResponse

   This exception type indicates that the variable-bindings of a Response-PDU
   do not constitute a valid response to the request. For example, if a GET
   request contains two OIDs, and the Response-PDU returns the two variables
   in the wrong order, then the request method (or the
   :meth:`RequestHandle.wait` method) will raise this error.

   .. py:data:: variableBindings
      :type: VarBindList

      The list of variable bindings from the Response-PDU.
