      `RFC 1157, Section 3.2.6.3`_ explains the relationship between the
      "names" of object types, and the "names" of the instances of an object
      type. The word "names" means OIDs.

      `RFC 2578, Section 7.7`_ specifies how an object is encoded as an
      ``INDEX``, including the meaning of the ``IMPLIED`` keyword.

      Every SNMP variable is identified by a "variable name", which is an OID
      with the format `x.y`, where `x` is the OID of an ``OBJECT-TYPE``,
      defined in a MIB file, and the `y` is an encoding of the ``INDEX``
      associated with that ``OBJECT-TYPE``.

      Let's look at an example of how we can find out what network interfaces a machine has. The ``IF-MIB`` (:rfc:`2863#section-6`) contains the following definition:

      .. code-block:: text

         ifDescr OBJECT-TYPE
             SYNTAX      DisplayString (SIZE (0..255))
             MAX-ACCESS  read-only
             STATUS      current
             DESCRIPTION
                     "A textual string containing information about the
                     interface.  This string should include the name of the
                     manufacturer, the product name and the version of the
                     interface hardware/software."
             ::= { ifEntry 2 }

      In order to request the ``ifDescr``, we have to figure out what OID ot use. The ``{ ifEntry 2 }`` bit at the end is MIB-speak for

      .. code-block:: python

         ifDescr = ifEntry.extend(2)

      If you look at the ``ifEntry`` definition, in the same file, you'll see that ``ifEntry`` is defined as ``{ ifTable 1 }``. If you follow the chain all the way up to ``iso(1)``, you'll come up with the complete OID for ``ifDescr``: ``"1.3.6.1.2.1.2.2.1.2"``.

      This is a good starting point. However, if I simply send a Get request with this 

      If I send a Get request for ``ifDescr`` (``"1.3.6.1.2.1.2.2.1.2"``), I will get a response of :class:`NoSuchObject`, because this is an ``OBJECT-TYPE`` OID, not an instance OID. To 

      For example, here's the definition of ``ifEntry`` type, from the ``IF-MIB``, representing a row of the ``ifTable``.

      .. code-block:: text

         ifEntry OBJECT-TYPE
             SYNTAX      IfEntry
             MAX-ACCESS  not-accessible
             STATUS      current
             DESCRIPTION
                     "An entry containing management information applicable to a
                     particular interface."
             INDEX   { ifIndex }
             ::= { ifTable 1 }

      The ``INDEX`` clause of this definition tells us that this table uses the ``ifIndex`` as the unique identifier for each row. The same MIB file tells us that the ``ifIndex`` is an ``InterfaceIndex`` type,

      .. code-block:: text

         ifIndex OBJECT-TYPE
             SYNTAX      InterfaceIndex
             MAX-ACCESS  read-only
             STATUS      current
             DESCRIPTION
                     "A unique value, greater than zero, for each interface.  It
                     is recommended that values are assigned contiguously
                     starting from 1.  The value for each interface sub-layer
                     must remain constant at least from one re-initialization of
                     the entity's network management system to the next re-
                     initialization."
             ::= { ifEntry 1 }

      which is a ``TEXTUAL-CONVENTION`` for an ``INTEGER`` between 1 and 2147483647.

      .. code-block: text

         InterfaceIndex ::= TEXTUAL-CONVENTION
             DISPLAY-HINT "d"
             STATUS       current
             DESCRIPTION
                     "A unique value, greater than zero, for each interface or
                     interface sub-layer in the managed system.  It is
                     recommended that values are assigned contiguously starting
                     from 1.  The value for each interface sub-layer must remain
                     constant at least from one re-initialization of the entity's
                     network management system to the next re-initialization."
             SYNTAX       Integer32 (1..2147483647)

      .. code-block:: python

         vblist = manager.get(ifDescr.withIndex(Integer(3)))


.. _RFC 1157, Section 3.2.6.3: https://datatracker.ietf.org/doc/html/rfc1157.html#section-3.2.6.3
.. _RFC 2578, Section 7.7: https://datatracker.ietf.org/doc/html/rfc2578.html#section-7.7
