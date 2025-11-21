Data Types
==========

.. module:: snmp.smi

This section describes several classes that implement types defined in `RFC 3416, Section 3`_\ .

``SimpleSyntax``
----------------

.. py:class:: Integer

   An alias for :class:`Integer32`.

.. py:class:: Integer32(value: int)

   The default ``INTEGER`` type for SNMP.

   The constructor raises a :class:`ValueError` if the `value` is not in the range of a 32-bit two's complement number.

   .. property:: value
      :type: int

      This object's value as a native :class:`int`.

   .. method:: __eq__ (self, other: object) -> bool

      Compare two ``INTEGER``\ s for equality both in value and in ASN.1 type.
      An :class:`Integer32` and an :class:`Unsigned32` with the same value are
      not equal because they differ in type.

.. py:class:: OctetString(data: bytes)

   A representation of an ASN.1 ``OCTET STRING``.

   The constructor raises a :class:`ValueError` if the `data` is longer than 65535 bytes.

   .. property:: data
      :type: bytes

      The object's raw data as a native :class:`bytes`.

   .. method:: __eq__ (self, other: object) -> bool

      Compare two ``OCTET STRINGS`` for equality both in value and in ASN.1 type. An :class:`OctetString` and an :class:`Opaque` containing the same data are not equal because they differ in type.

.. class:: OID(* subidentifiers)

   A representation of an ASN.1 ``OBJECT IDENTIFIER``.

   The `subidentifiers` argument list accepts between 0 and 128 integers. The first sub-identifier must be between ``0`` and ``2``, the second must be between ``0`` and ``39``, and the rest must be between ``0`` to ``(2^32)-1``. The encoding rules do not support OIDs with less than 2 sub-identifiers, so when sent over the wire, the objects ``OID()``, ``OID(0)``, ``OID(1)``, and ``OID(2)`` become ``OID(0, 0)``, ``OID(0, 0)``, ``OID(1, 0)``, and ``OID(2, 0)``, respectively.

   The methods in this class are all non-mutating. The descriptions sometimes use words like "append" as shorthand for "return a new instance containing the sub-identifiers of this object followed by one or more additional subidentifier(s)."

   .. method:: parse(oid: str) -> OID
      :classmethod:

      Convert a string like ``"1.3.6.1.2.1.1.1.0"`` or ``".1.3.6.1.2.1.1.1.0"``
      into an :class:`OID`. Raise a :class:`ValueError` if `oid` does not
      represent a valid :class:`OID`.

   .. method:: __str__() -> str

      Convert an :class:`OID` into a string like ``"1.3.6.1.2.1.1.1.0"``.

   .. method:: __hash__() -> int

      This allows an :class:`OID` to be used as a key in a :class:`dict`.

   .. method:: __eq__(other: object) -> bool

      Compare two :class:`OID`\ s for equality.

   .. method:: __lt__(other: OID) -> bool

      Compare two :class:`OID`\ s lexicographically.

   .. method:: __len__() -> int

      Count the number of sub-identifiers.

   .. method:: __getitem__(n: int | slice) -> int | tuple[int, ...]

      Retrieve the sub-identifier(s) at index (or slice) `n`.

   .. method:: __iter__() -> Iterator[int]

      Iterate through the sub-identifiers.

   .. method:: extend(* subidentifiers: int) -> OID

      Append the given `subidentifiers`. Raise a :class:`ValueError` if the result would be longer than 128 sub-identifiers.

   .. method:: startswith(prefix: OID) -> bool

      Similar to :meth:`str.startswith`.

   .. method:: withIndex( \
         * index: Integer | OctetString | OID, \
         implied: bool = False \
      ) -> OID

      Construct an SNMP variable name from an object type name and an index. This operation is the reverse of :meth:`getIndex` and :meth:`decodeIndex`.

      For example, the following code requests the description of interface 3:

      .. code-block:: python

         ifDescr = OID.parse("1.3.6.1.2.1.2.2.1.2")
         vb, = manager.get(ifDescr.withIndex(Integer(3)))
         print(f"Description: {vb.value.data}")

      In rare cases, the last variable in the ``INDEX`` clause is labelled as ``IMPLIED``. For example, here's a definition from the ``SNMP-NOTIFICATION-MIB``:

      .. code-block:: text

         snmpNotifyFilterEntry OBJECT-TYPE
             SYNTAX      SnmpNotifyFilterEntry
             MAX-ACCESS  not-accessible
             STATUS      current
             DESCRIPTION
                 "An element of a filter profile.

                  Entries in the snmpNotifyFilterTable are created and
                  deleted using the snmpNotifyFilterRowStatus object."
             INDEX {         snmpNotifyFilterProfileName,
                     IMPLIED snmpNotifyFilterSubtree }
             ::= { snmpNotifyFilterTable 1 }

      When encoding such an index, you must set the `implied` argument to ``True``.

      This method raises a :class:`ValueError` if the result would be longer than 128 sub-identifiers.

      Additional Reading
      ******************

      `RFC 1157, Section 3.2.6.3`_ explains the relationship between the
      "names" of object types, and the "names" of the instances of an object
      type. The word "names" means OIDs.

      `RFC 2578, Section 7.7`_ specifies how an object is encoded as an
      ``INDEX``, including the meaning of the ``IMPLIED`` keyword.

   .. method:: getIndex(prefix: OID, cls=Integer, implied=False)

      Decode the index portion of an SNMP variable name, so long as the index is a single value. For a multi-part index, use :meth:`decodeIndex`.

      For example, this snippet requests the first interface description in ``ifTable``, and uses the returned :class:`OID` to determine its ``ifIndex``.

      .. code-block:: python

         ifDescr = OID.parse("1.3.6.1.2.1.2.2.1.2")
         vb, = manager.getNext(ifDescr)
         index = vb.name.getIndex(ifDescr).value
         description = vb.value.data
         print(f"Description for interface {index}: {description}")

      You can also use the `cls` parameter to decode a non-:class:`Integer` index. Here is a contrived example of this:

      .. code-block:: python

         prefix = OID.parse("1.2.3.4")
         oid = prefix.extend(5, 1, 2, 3, 4, 5)
         index = oid.getIndex(prefix, OID)
         print(index)   # prints "1.2.3.4.5"

      In rare cases, the variable in the ``INDEX`` clause is labelled as ``IMPLIED``. For example, here's a definition from the ``SNMP-NOTIFICATION-MIB``:

      .. code-block:: text

         snmpNotifyEntry OBJECT-TYPE
             SYNTAX      SnmpNotifyEntry
             MAX-ACCESS  not-accessible
             STATUS      current
             DESCRIPTION
                 "An entry in this table selects a set of management targets
                  which should receive notifications, as well as the type of

                  notification which should be sent to each selected
                  management target.

                  Entries in the snmpNotifyTable are created and
                  deleted using the snmpNotifyRowStatus object."
             INDEX { IMPLIED snmpNotifyName }
             ::= { snmpNotifyTable 1 }

      When decoding such an index, you must set the `implied` argument to ``True``.

      If the :class:`OID` does not begin with `prefix`, this method will raise a :class:`BadPrefix` exception. If there is a problem decoding the index, it will raise an :class:`IndexDecodeError`.

   .. method:: decodeIndex(prefix: OID, * types: type, implied=False) -> tuple[...]

      Decode the index portion of an SNMP variable name.

      .. note::

         This method always returns the index as a tuple, even if the length is 1. It is therefore recommended to use :meth:`getIndex` when the index consists of a single value.

      Here's a real object type definition from the ``IP-MIB``:

      .. code-block:: text

         ipAddressPrefixEntry OBJECT-TYPE
             SYNTAX     IpAddressPrefixEntry
             MAX-ACCESS not-accessible
             STATUS     current
             DESCRIPTION
                    "An entry in the ipAddressPrefixTable."
             INDEX    { ipAddressPrefixIfIndex, ipAddressPrefixType,
                        ipAddressPrefixPrefix, ipAddressPrefixLength }
             ::= { ipAddressPrefixTable 1 }

      Notice that there are four variables in the ``INDEX``. You can determine the data type of each variable by tracing their ``SYNTAX`` clauses until you get to a primitive type. You can then decode the index by passing the corresponding classes to :meth:`decodeIndex` via the `types` argument list. Here is a code sample that does just that:

      .. code-block:: python

         ipAddressPrefixOrigin = OID.parse("1.3.6.1.2.1.4.32.1.5")
         vb, = manager.getNext(ipAddressPrefixOrigin)
         index = vb.name.decodeIndex(
            ipAddressPrefixOrigin,
            Integer,
            Integer,
            OctetString,
            Integer,
         )

         print(f"ifIndex: {index[0].value}")
         print(f"type: {index[1].value}")
         print(f"prefix: {index[2].data}")
         print(f"length: {index[3].value}")
         print(f"origin: {vb.value.value}")

      In rare cases, the last variable in the ``INDEX`` clause is labelled as ``IMPLIED``. For example, here's a definition from the ``SNMP-NOTIFICATION-MIB``:

      .. code-block:: text

         snmpNotifyFilterEntry OBJECT-TYPE
             SYNTAX      SnmpNotifyFilterEntry
             MAX-ACCESS  not-accessible
             STATUS      current
             DESCRIPTION
                 "An element of a filter profile.

                  Entries in the snmpNotifyFilterTable are created and
                  deleted using the snmpNotifyFilterRowStatus object."
             INDEX {         snmpNotifyFilterProfileName,
                     IMPLIED snmpNotifyFilterSubtree }
             ::= { snmpNotifyFilterTable 1 }

      When decoding such an index, you must set the `implied` argument to ``True``.

      If the :class:`OID` does not begin with `prefix`, this method will raise a :class:`BadPrefix` exception. If there is a problem decoding the index, it will raise an :class:`IndexDecodeError`.

   .. exception:: BadPrefix

   .. exception:: IndexDecodeError

``ApplicationSyntax``
---------------------

.. py:class:: IpAddress(addr: str)

   An IPv4 address. The constructor raises a :class:`ValueError` if the `addr` is not a valid IPv4 address string.

   This is an ``OCTET STRING`` type, so it implements the same interface as :class:`OctetString`.

   .. property:: addr
      :type: str

      The address in human-readable ``"X.X.X.X"`` format.

   .. property:: data
      :type: bytes

      A byte string encoding the address in network format.

   .. method:: __eq__ (self, other: object) -> bool

      Two :class:`IpAddress`\es are equal if they represent the same address.

.. py:class:: Counter32(value: int)

   This class is exactly like :class:`Integer32`, but allows only 32-bit unsigned values.

   .. property:: value
      :type: int

      This object's value as a native :class:`int`.

   .. method:: __eq__ (self, other: object) -> bool

      Compare two ``INTEGER``\ s for equality both in value and in ASN.1 type.

.. py:class:: Unsigned

   An alias for :class:`Unsigned32`.

.. py:class:: Unsigned32(value: int)

   This class is exactly like :class:`Integer32`, but allows only 32-bit unsigned values.

   .. property:: value
      :type: int

      This object's value as a native :class:`int`.

   .. method:: __eq__ (self, other: object) -> bool

      Compare two ``INTEGER``\ s for equality both in value and in ASN.1 type.

.. py:class:: Gauge32(value: int)

   Indistinguishable from :class:`Unsigned32` in all but name.

.. py:class:: TimeTicks(value: int)

   This class is exactly like :class:`Integer32`, but allows only 32-bit unsigned values.

   .. property:: value
      :type: int

      This object's value as a native :class:`int`.

   .. method:: __eq__ (self, other: object) -> bool

      Compare two ``INTEGER``\ s for equality both in value and in ASN.1 type.

.. py:class:: Opaque(data: bytes)

   This class is exactly like :class:`OctetString`.

   .. property:: data
      :type: bytes

      The object's raw data as a native :class:`bytes`.

   .. method:: __eq__ (self, other: object) -> bool

      Compare two ``OCTET STRINGS`` for equality both in value and in ASN.1 type.

.. py:class:: Counter64(value: int)

   This class is exactly like :class:`Integer32`, but allows only 64-bit unsigned values.

   .. property:: value
      :type: int

      This object's value as a native :class:`int`.

   .. method:: __eq__ (self, other: object) -> bool

      Compare two ``INTEGER``\ s for equality both in value and in ASN.1 type.

Variable Bindings
-----------------

.. py:class:: Null()

   A placeholder value for requests.

.. py:class:: NoSuchObject()

   A special value in a response that means that the requested OID does not refer to a known object type.

   .. method:: __eq__(self, other: object) -> bool

      Check if `other` is an instance of :class:`NoSuchObject`.

.. py:class:: NoSuchInstance()

   A special value in a response meaning that the OID refers to a known object type, but there is no instance with the requested OID index.

   .. method:: __eq__(self, other: object) -> bool

      Check if `other` is an instance of :class:`NoSuchInstance`.

.. py:class:: EndOfMibView()

   A special value in a response to a GetNext or GetBulk request meaning that there are no variables following the requested OID.

   .. method:: __eq__(self, other: object) -> bool

      Check if `other` is an instance of :class:`EndOfMibView`.

.. py:class:: VarBind(oid: OID | str, value: Optional[Integer | OctetString | OID] = None)

   .. property:: name
      :type: OID

      The variable name, as an :class:`OID`.

   .. property:: value
      :type: Integer | OctetString | Null | OID

      The variable value, which will be one of the types described on this page.

.. py:class:: VarBindList(*varbinds: VarBind)

   A ``SEQUENCE`` of :class:`VarBind`\ s.

   .. method:: __len__() -> int

      Count the number of variable bindings in this list.

   .. method:: __getitem__(n: int | slice) -> VarBind | tuple[VarBind, ...]

      Retrieve the :class:`VarBind`\ (s) at index (or slice) `n`.

   .. method:: __iter__() -> Iterator[VarBind]

      Iterate through the :class:`VarBind`\ s.

Constants
---------

.. py:data:: zeroDotZero

   The :class:`OID` representing ``"0.0"``. This is the OID equivalent of ``NULL``.

.. _RFC 1157, Section 3.2.6.3: https://datatracker.ietf.org/doc/html/rfc1157.html#section-3.2.6.3
.. _RFC 2578, Section 7.7: https://datatracker.ietf.org/doc/html/rfc2578.html#section-7.7
.. _RFC 3416, Section 3: https://datatracker.ietf.org/doc/html/rfc3416.html#section-3
