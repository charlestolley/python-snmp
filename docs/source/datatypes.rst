Data Types
==========

ASN.1 Data Types
----------------

.. class:: ASN1
   :canonical: snmp.asn1.ASN1

   This is the abstract base class for all ASN.1 data types in this library. It
   defines the following two methods, which implement ASN.1 encoding and
   decoding under the Basic Encoding Rules (BER):

   .. method:: decode(data, leftovers=False)
      :classmethod:

      Create a new object by decoding it from the byte string `data`. In the
      default case, this method expects to consume the entire string. If `data`
      encodes multiple objects, then `leftovers` should be set to ``True``, in
      which case the leftover portion of the data will be returned as well
      (i.e.  it will return a tuple containing both the decoded object and the
      leftover data).

      If the data cannot be decoded as requested, a
      :class:`snmp.ber.ParseError` will be raised.

   .. method:: encode()

      Encode an object into a byte-string. This method is not expected to raise
      any exceptions.

Core Data Types
^^^^^^^^^^^^^^^

.. class:: snmp.smi.Integer(value)

   This class represents an ASN.1 INTEGER, which is restricted to a 32-bit
   signed integer by the SNMP SMIv2 (see :rfc:`2578#section-2`).

   .. property:: value

      The object's value as a native :class:`int`.

   .. method:: __eq__ (self, other)

      Two INTEGER types are equal if they have the same value *and* the same
      ASN.1 tag. For example, an :class:`Unsigned` and a :class:`Gauge32` with
      the same value are equal, but an :class:`Unsigned` is never equal to an
      :class:`Integer`.

.. class:: snmp.smi.OctetString(data)

   This class represents an ASN.1 OCTET STRING, which is restricted to a
   maximum of 65535 octets in length by the SNMP SMIv2 (see
   :rfc:`2578#section-2`).

   .. property:: data

      The object's raw data as a bytes-like object.

   .. method:: __eq__ (self, other)

      Two OCTET STRINGs are equal if they represent the same bytes *and* use
      the same ASN.1 tag.

.. class:: snmp.smi.Null()

   This class represents the built-in ASN.1 NULL type. It is also the base
   class for types like :class:`EndOfMibView`.

   .. method:: __eq__ (self, other)

      Two NULL objects are equal if they have the same ASN.1 tag.

.. class:: snmp.smi.OID(* subidentifiers)

   This class represents an ASN.1 Object Identifier. An object identifier is
   a sequence of up to 128 integers (called sub-identifiers) that describe a
   path to a node in the MIB tree. For an explanation of the MIB tree, consult
   :rfc:`2578`. Object identifiers are normally expressed in string by placing
   a dot between each sub-identifier, like this: ``"1.3.6.1.2.1.1.1"``.

   Sub-identifiers are limited to the range ``0`` to ``(2^32)-1``, with the
   exception of the first two; the first must be between ``0`` and ``2``, and
   the second must be between ``0`` and ``39``. Because of the encoding rules,
   it is not possible to send an OID with less than two sub-identifiers. This
   class can be instantiated with zero or one sub-identifiers, but, when
   encoded, will be treated as if there were implicit zeros at the end.

   .. method:: parse(oid)
      :classmethod:

      This method serves as an alternate way to call the constructor. It parses
      an OID string (e.g. ``"1.3.6.1.2.1.1.1"``) and returns an :class:`OID`
      object. OID strings may also contain a leading dot before the first
      sub-identifier.

   .. method:: __str__()

      Return the standard dot-separated representation of the OID.

   .. method:: __lt__(other)

      Compare two OIDs lexicographically (that's the word the RFCs use).

   .. method:: __len__()

      Return the number of sub-identifiers in the OID.

   .. method:: __getitem__(n)

      The square bracket operator returns sub-identifier `n`, or raises and
      :class:`IndexError`. `n` may also be a :class:`slice`, in which case the
      result is a tuple.

   .. method:: __iter__()

      Return an object to iterate over the sub-identifiers.

   .. method:: extend(* subidentifiers)

      Append the given sub-identifiers to the OID and return it as a new
      object.

   .. method:: withIndex(* index, implied=False)

      Every SNMP object is identified by an OID with a format of
      `<prefix>.<index>`, where the prefix refers to an object type definied in
      the MIB, and the index encodes one or more primitive objects. This is
      explained in :rfc:`1157#section-3.2.6.3`.

      This method encodes the given object(s), as outlined in
      :rfc:`2578#section-7.7`, and appends the encoding(s) to the end of the
      OID, returning a new object. For an ``INDEX`` with the ``IMPLIED``
      keyword attached to the final object, set the `implied` parameter to
      ``True``.

   .. method:: decodeIndex(prefix, * types, implied=False)

      This method is the reverse of :meth:`withIndex`. The `prefix` argument
      is an OID referring to an object definition in the MIB, and the `types`
      argument gives the expected type of each object in the index. Most
      indices contain a single object, in which case the :meth:`getIndex`
      wrapper function may be more convenient. 

      If the OID does not begin with the given prefix, this method will raise a
      :class:`snmp.smi.OID.BadPrefix` exception. If the prefix does match,
      but the index cannot be decoded, it will raise an
      :class:`snmp.smi.OID.IndexDecodeError`. The index is returned as a tuple
      whose length matches the length of `types`.

      The 'implied' argument affects the decoding of :class:`OctetString` and
      :class:`OID` objects. The encoding normally begins with a length byte,
      but the MIB may mark the final object in an ``INDEX`` with the
      ``IMPLIED`` keyword, indicating that the encoding occupies the remainder
      of the OID.

   .. method:: getIndex(prefix, cls=Integer, implied=False)

      This method wraps a call to :meth:`decodeIndex` for an index consisting
      of only a single object. Where that method returns a tuple of length 1,
      this method returns the object directly.

   .. method:: startswith(prefix)

      Similar to :meth:`str.startswith`, this method checks whether an OID
      begins with `prefix`, indicating that `prefix` represents a parent node
      in the conceptual MIB tree.

Additional Data Types
^^^^^^^^^^^^^^^^^^^^^

.. class:: snmp.smi.Unsigned(value)

   An INTEGER with a value between ``0`` and ``(2^32)-1``.

   .. property:: value

   .. method:: __eq__ (self, other)

      See :meth:`Integer.__eq__`.

.. class:: snmp.smi.Integer32(value)

   :class:`snmp.smi.Integer` is an alias for Integer32.

   .. property:: value

.. class:: snmp.smi.Unsigned32(value)

   :class:`snmp.smi.Unsigned` is an alias for Unsigned32.

   .. property:: value

.. class:: snmp.smi.IpAddress(addr)

   An IPv4 address.

   .. property:: addr

      The address in human-readable "X.X.X.X" format.

   .. property:: data

      A byte string encoding the address in network format.

   .. method:: __eq__ (self, other)

      Two :class:`IpAddress`\es are equal if they represent the same address.

.. class:: snmp.smi.Counter32(value)

   An INTEGER with a value between ``0`` and ``(2^32)-1``, used to represent
   monotonically increasing values that wrap to zero upon overflow.

   .. property:: value

   .. method:: __eq__ (self, other)

      See :meth:`Integer.__eq__`.

.. class:: snmp.smi.Gauge32(value)

   An INTEGER with a value between ``0`` and ``(2^32)-1``, used to represent
   values within a specific range that do not wrap.

   .. property:: value

   .. method:: __eq__ (self, other)

      See :meth:`Integer.__eq__`.

.. class:: snmp.smi.TimeTicks(value)

   An INTEGER with a value between ``0`` and ``(2^32)-1``, used to represent
   time measurements in hundredths of a second.

   .. property:: value

   .. method:: __eq__ (self, other)

      See :meth:`Integer.__eq__`.

.. class:: snmp.smi.Opaque(data)

   This data type is deprecated since SNMPv2c.

   .. property:: data

   .. method:: __eq__ (self, other)

      See :meth:`Integer.__eq__`.

.. class:: snmp.smi.Counter64(value)

   An INTEGER with a value between ``0`` and ``(2^64)-1``, with similar
   semantics to Counter32.

   .. property:: value

   .. method:: __eq__ (self, other)

      See :meth:`Integer.__eq__`.

PDU Data Types
^^^^^^^^^^^^^^

.. class:: snmp.pdu.NoSuchObject

   A special value sent in a response to indicate that the requested OID is
   unknown to the remote engine.

.. class:: snmp.pdu.NoSuchInstance

   A special value sent in a response to indicate that there is no object
   associated with the requested OID.

.. class:: snmp.pdu.EndOfMibView

   A special value sent in response to a Get-Next or Get-Bulk request to
   indicate that there are no more objects to return.

.. class:: snmp.pdu.VarBind(name, value=None)

   An SNMP variable binding pairs an OID with a value. In actual usage, the
   OID (i.e. the "name") consists of a prefix, which refers to an object
   definition in the MIB, and an index, identifying a unique instance of that
   object for a specific engine. The value is an instance of the type specified
   in the object definition. For requests, the "name" may be any OID, and the
   value should be :class:`Null`.

   The `name` argument to the constructor may either be an :class:`OID` object,
   or it may be an OID string. The value may be any SNMP object, or ``None``,
   for a :class:`Null` value.

   .. property:: name

      The "name" of the variable, which is an OID.

   .. property:: value

      The variable's value, which is some instance of :class:`Asn1Encodable`.

.. class:: snmp.pdu.VarBindList(* args)

   A VarBindList is a container for :class:`VarBind` objects. The constructor
   accepts any number of VarBinds, OIDs, or OID strings.

   .. method:: __len__()

      Return the number of variable bindings in this list.

   .. method:: __getitem__(n)

      Retrieve a variable binding, or a tuple of variable bindings, from the
      list.

   .. method:: __iter__()

      Return an object to iterate over the variable bindings in this list.

.. class:: snmp.pdu.PDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

   SNMP defines several different Protocol Data Units (PDUs), each representing
   a specific operation, or message type. All PDUs follow the same structure,
   with three Integer fields containing metadata, and a list of variable
   bindings (VarBindList). Each variable binding consists of a name and a
   value, as described in the :class:`VarBind` class documentation. This is the
   base class for all PDU types, except for :class:`GetBulkRequestPDU`, which
   uses its metadata fields differently than the others.

   When constructing a PDU object, the variable bindings are provided as
   positional arguments. These may be instances of :class:`VarBind`, but they
   can also be OIDs, either as an :class:`OID` object, or in string format. If
   OIDs are used, then the VarBinds will be populated with :class:`Null`
   values.

   .. property:: requestID

      The request ID is an arbitrary number used to match up responses to
      requests.

   .. property:: errorStatus

      A non-zero error status in a response indicates that an error occured in
      the processing of the request. Allowable error status values, as well as
      their names, are enumerated in the :class:`PDU.ErrorStatus` class. If the
      error relates to a specific variable binding, then the :attr:`errorIndex`
      field will also contain a non-zero value.

   .. property:: errorIndex

      When a response contains a non-zero error status, this field indicates
      the source of the error. A value of ``0`` indicates that the error
      relates to the message as a whole. A value greater than ``0`` gives the
      index of the variable binding that caused the error. Note that this means
      that index ``1`` refers to the first variable binding in the list.

   .. property:: variableBindings

      This property gives access to the :class:`VarBindList` containing the
      message's variable bindings.

   .. class:: ErrorStatus(errorStatus)

      This :class:`IntEnum` class enumerates the possible values of the
      :attr:`errorStatus` field. Note that some values are only valid in newer
      versions of SNMP.

.. class:: snmp.pdu.GetRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.GetNextRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.ResponsePDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.SetRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.TrapPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.GetBulkRequestPDU( \
      * varbinds, \
      requestID=0, \
      nonRepeaters=0, \
      maxRepetitions=0, \
   )

   .. property:: requestID

      Same as :attr:`PDU.requestID`.

   .. property:: nonRepeaters

      This field is explained briefly on the :doc:`manager` page.

   .. property:: maxRepetitions

      This field is explained briefly on the :doc:`manager` page.

   .. property:: variableBindings

      Same as :attr:`PDU.variableBindings`.

.. class:: snmp.pdu.InformRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.SNMPv2TrapPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.ReportPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )

.. class:: snmp.pdu.ErrorResponse()

   .. py:attribute:: status
      :type: snmp.pdu.PDU.ErrorStatus

      Contains the ``error-status`` from the ``ResponsePDU`` that triggered
      this exception.

   .. py:attribute:: cause
      :type: snmp.pdu.PDU | snmp.pdu.VarBind | int

      Indicates the portion of the request that caused the failure. It is
      expected to to refer either to the request PDU itself, or to a single
      :class:`snmp.pdu.VarBind` from the request. However, if ``error-index``
      field of the response is invalid, then this attribute will contain the
      ``error-index`` itself.
