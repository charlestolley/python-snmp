Data Types
==========

.. module:: snmp.smi

.. class:: snmp.smi.OID(* subidentifiers)

   A representation of an ASN.1 Object Identifier.

   The `subidentifiers` argument list accepts between 0 and 128 integers. The first sub-identifier must be between ``0`` and ``2``, the second must be between ``0`` and ``39``, and the rest must be between ``0`` to ``(2^32)-1``. The encoding rules do not support OIDs with less than 2 sub-identifiers, so when sent over the wire, the objects ``OID()``, ``OID(0)``, ``OID(1)``, and ``OID(2)`` become ``OID(0, 0)``, ``OID(0, 0)``, ``OID(1, 0)``, and ``OID(2, 0)``, respectively.

   The methods in this class are all non-mutating. The descriptions sometimes use words like "append" as shorthand for "return a new instance containing the sub-identifiers of this object followed by one or more additional subidentifier(s)."

   .. method:: parse(oid: str) -> OID
      :classmethod:

      Convert a string like ``"1.3.6.1.2.1.1.1.0"`` or ``".1.3.6.1.2.1.1.1.0"``
      into an :class:`OID`.

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

      If `n` is an :class:`int`, return the sub-identifier at position `n`, or
      raise an :class:`IndexError`, if `n` is out of range. If `n` is a
      :class:`slice`, return a range of sub-identifiers as a :class:`tuple` of
      :class:`int`\ s.

   .. method:: __iter__() -> Iterator[int]

      Iterate through the sub-identifiers.

   .. method:: extend(* subidentifiers: int) -> OID

      Append the given `subidentifiers`.

   .. method:: startswith(prefix: OID) -> bool

      Similar to :meth:`str.startswith`.

   .. method:: withIndex( \
         * index: Integer | OctetString | OID | IpAddress, \
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

      Notice that there are four variables in the ``INDEX``. You can determine the data type of each variable their ``SYNTAX`` clauses until you get to a primitive type. You can then decode the index by passing the corresponding classes to :meth:`decodeIndex` via the `types` argument list. Here is some code that does just that:

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

.. py:data:: zeroDotZero

   The :class:`OID` representing "0.0". This is the OID equivalent of ``NULL``.

.. py:class:: OctetString

.. py:class:: Integer

.. py:class:: Integer32

.. py:class:: Unsigned

.. py:class:: Unsigned32

.. py:class:: Counter32

.. py:class:: Counter64

.. py:class:: Gauge32

.. py:class:: TimeTicks

.. py:class:: Null

.. py:class:: IpAddress

.. py:class:: Opaque

.. py:class:: NoSuchObject

.. py:class:: NoSuchInstance

.. py:class:: EndOfMibView

Integer Types:


OctetString Types:

.. py:class:: VarBind

.. py:class:: VarBindList
