Data Types
==========

``snmp.types``
--------------

.. class:: Asn1Encodable
   :canonical: snmp.types.Asn1Encodable

   This is the base class for all other classes documented here. It defines the
   API for encoding and decoding SNMP objects to and from the byte strings that
   are sent across the network. It also defines the ``==`` equality operator, as
   well as the less-strict :meth:`equals` method.

   .. method:: decode(data, leftovers=False, copy=True)
      :classmethod:

      Create a new object by decoding it from the byte string `data`. In the
      default case, this method expects to consume the entire string. If `data`
      encodes multiple objects, then `leftovers` should be set to ``True``, in
      which case the leftover portion of the data will be returned as well (i.e.
      it will return a tuple containing both the decoded object and the leftover
      data).

      The `copy` argument determines whether the decoded object will contain
      a reference to the original data, or a copy. This has nothing to do with
      performance, and everything to do with computing message signatures when
      message authentication is required.

      If the data cannot be decoded as requested, a :class:`snmp.ber.ParseError`
      will be raised.

   .. method:: encode()

      Encode an object into a byte-string. This method may throw an exception if
      the object contains an invalid value, but should succeed otherwise.

   .. method:: __eq__(other)

      The `==` operator performs a strict equality check, which returns ``True``
      if and only if the two objects are of the exact same type, and also have
      the same value, as determined by the :meth:`equals` method.

   .. method:: equals(other)

      This method checks whether two objects represent equal values, regardless
      of the exact type. The two types, however, must at least derive from the
      same base class, one of :class:`Integer`, :class:`OctetString`,
      :class:`Null`, :class:`OID`, or they may be two sequence types.

.. class:: Integer(value)
   :canonical: snmp.types.Integer

   This is the base class for all other integral types. On its own, it
   represents the built-in ASN.1 INTEGER type, which is restricted to a 32-bit
   signed integer by the SMIv2 (see :rfc:`2578#section-2`).

   .. property:: value

      The object's value as a native :class:`int`.

.. class:: OctetString(data)
   :canonical: snmp.types.OctetString

   This class represents the built-in ASN.1 OCTET STRING type. It may be
   subclassed to implement other types such as :class:`IpAddress`.

   .. property:: data

      The object's raw data as a bytes-like object.

.. class:: Null()
   :canonical: snmp.types.Null

   This class represents the built-in ASN.1 NULL type. It is also the base class
   for types like :class:`EndOfMibView`.

.. class:: OID(* nums)
   :canonical: snmp.types.OID

   This class represents an ASN.1 Object Identifier. An object identifier is
   a sequence of up to 255 integers (called sub-identifiers) that describe a
   path to a node in the MIB tree. For an explanation of the MIB tree, consult
   :rfc:`2578`. Object identifiers are normally expressed in string by placing
   a dot between each sub-identifier, like this: ``"1.3.6.1.2.1.1.1"``.

   Sub-identifiers are limited to the range ``0`` to ``(2^32)-1``, with the
   exception of the first two; the first must be between ``0`` and ``2``, and
   the second must be between ``0`` and ``39``. Because of the encoding rules,
   it is not possible to send an OID with less than two sub-identifiers. This
   class can be instantiated with zero or one sub-identifiers, but, when
   encoded, will be treated as if there were implicit zeros at the end.

   Lastly, every instance of this class is treated as a value type, meaning that
   its contents are immutable. Methods such as :meth:`extend`, which modify the
   the value, always return a new object, and leave the original unchanged.

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

      The square bracket operator returns sub-identifier `n`, where `n` is an
      integer between ``0`` and the length of the OID minus one. `n` may also
      be a :class:`slice`, in which case the result is a tuple.

   .. method:: __iter__()

      Return an object to iterate over the sub-identifiers.

   .. method:: extend(* nums)

      Append the given sub-identifiers to the OID and return it as a new object.

   .. method:: appendIndex(* index)

      Every SNMP object is identified by an OID with a format of
      `<prefix>.<index>`, where the prefix refers to an object type definied in
      the MIB, and the index encodes one or more primitive objects. This is
      explained in :rfc:`1157#section-3.2.6.3`.

      This method encodes the given object(s), as outlined in
      :rfc:`2578#section-7.7`, and appends the encoding(s) to the end of the
      OID, returning a new object.

   .. method:: extractIndex(prefix, * types)

      This method is the reverse of :meth:`appendIndex`. The `prefix` argument
      is an OID referring to an object definition in the MIB, and the `types`
      argument gives the expected type of each object in the index. Most
      indices contain a single object, in which case the :meth:`getIndex`
      wrapper function may be more convenient. 

      If the OID does not begin with the given prefix, this method will raise a
      :class:`snmp.types.OID.BadPrefix` exception. If the prefix does match,
      but the index cannot be decoded, it will raise an
      :class:`snmp.types.OID.IndexDecodeError`. The index is returned as a tuple
      whose length matches the length of `types`.

   .. method:: getIndex(prefix, cls=Integer)

      This method wraps a call to :meth:`extractIndex` for an index consisting
      of only a single object. Where that method returns a tuple of length 1,
      this method returns the object directly.

``snmp.smi``
------------

.. class:: Unsigned(value)
   :canonical: snmp.smi.Unsigned

   This class represents a 32-bit unsigned integer.

   .. property:: value

.. class:: Integer32(value)
   :canonical: snmp.smi.Integer32

   This class is indistinguishable from :class:`snmp.types.Integer`.

   .. property:: value

.. class:: Unsigned32(value)
   :canonical: snmp.smi.Unsigned32

   This class is indistinguishable from :class:`snmp.types.Unsigned`.

   .. property:: value

.. class:: IpAddress(addr)
   :canonical: snmp.smi.IpAddress

   An IPv4 address.

   .. property:: addr

      The address in human-readable "X.X.X.X" format.

   .. property:: data

      A byte string encoding the address in network format.

.. class:: Counter32(value)
   :canonical: snmp.smi.Counter32

   A 32-bit unsigned integer used to represent monotonically increasing values
   that wrap to zero upon overflowing.

   .. property:: value

.. class:: Gauge32(value)
   :canonical: snmp.smi.Gauge32

   A 32-bit unsigned integer used to represent values within a specific range
   that do not wrap.

   .. property:: value

.. class:: TimeTicks(value)
   :canonical: snmp.smi.TimeTicks

   A 32-bit unsigned integer used to represent time measurements in hundredths
   of a second.

   .. property:: value

.. class:: Opaque(data)
   :canonical: snmp.smi.Opaque

   This data type is deprecated since SNMPv2c.

   .. property:: data

.. class:: Counter64(value)
   :canonical: snmp.smi.Counter64

   A 64-bit unsigned integer with similar semantics to Counter32.

   .. property:: value

``snmp.pdu``
------------

.. class:: NoSuchObject
   :canonical: snmp.pdu.NoSuchObject

   A special value sent in a response to indicate that the requested OID is
   unknown to the remote engine.

.. class:: NoSuchInstance
   :canonical: snmp.pdu.NoSuchInstance

   A special value sent in a response to indicate that there is no object
   associated with the requested OID.

.. class:: EndOfMibView
   :canonical: snmp.pdu.EndOfMibView

   A special value sent in response to a Get-Next or Get-Bulk request to
   indicate that there are no more objects to return.

.. class:: VarBind(name, value=None)
   :canonical: snmp.pdu.VarBind

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

.. class:: VarBindList(* args)
   :canonical: snmp.pdu.VarBindList

   A VarBindList is a container for :class:`VarBind` objects. The constructor
   accepts any number of VarBinds, OIDs, or OID strings.

   .. method:: __len__()

      Return the number of variable bindings in this list.

   .. method:: __getitem__(n)

      Retrieve a variable binding, or a tuple of variable bindings, from the
      list.

   .. method:: __iter__()

      Return an object to iterate over the variable bindings in this list.

.. class:: PDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.PDU

   SNMP defines several different Protocol Data Units (PDUs), each representing a
   specific operation, or message type. All PDUs follow the same structure, with
   three Integer fields containing metadata, and a list of variable bindings
   (VarBindList). Each variable binding consists of a name and a value, as
   described in the :class:`VarBind` class documentation. This is the base class
   for all PDU types, except for :class:`GetBulkRequestPDU`, which uses its
   metadata fields differently than the others.

   When constructing a PDU object, the variable bindings are provided as
   positional arguments. These may be instances of :class:`VarBind`, but they
   can also be OIDs, either as an :class:`OID` object, or in string format. If
   OIDs are used, then the VarBinds will be populated with :class:`Null` values.

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

      When a response contains a non-zero error status, this field indicates the
      source of the error. A value of ``0`` indicates that the error relates to
      the message as a whole. A value greater than ``0`` gives the index of the
      variable binding that caused the error. Note that this means that index
      ``1`` refers to the first variable binding in the list.

   .. property:: variableBindings

      This property gives access to the :class:`VarBindList` containing the
      message's variable bindings.

   .. class:: ErrorStatus(errorStatus)

      This :class:`IntEnum` class enumerates the possible values of the
      :attr:`errorStatus` field. Note that some values are only valid in newer
      versions of SNMP.

.. class:: GetRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.GetRequestPDU

.. class:: GetNextRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.GetNextRequestPDU

.. class:: ResponsePDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.ResponsePDU

.. class:: SetRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.SetRequestPDU

.. class:: TrapPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.TrapPDU

.. class:: GetBulkRequestPDU( \
      * varbinds, \
      requestID=0, \
      nonRepeaters=0, \
      maxRepetitions=0, \
   )
   :canonical: snmp.pdu.GetBulkRequestPDU

   .. property:: requestID

      Same as :attr:`PDU.requestID`.

   .. property:: nonRepeaters

      This field is explained briefly on the :doc:`manager` page.

   .. property:: maxRepetitions

      This field is explained briefly on the :doc:`manager` page.

   .. property:: variableBindings

      Same as :attr:`PDU.variableBindings`.

.. class:: InformRequestPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.InformRequestPDU

.. class:: SNMPv2TrapPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.SNMPv2TrapPDU

.. class:: ReportPDU( \
      * varbinds, \
      requestID=0, \
      errorStatus=0, \
      errorIndex=0, \
   )
   :canonical: snmp.pdu.ReportPDU
