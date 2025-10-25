``snmp`` --- Simple Network Management Protocol
===============================================

.. toctree::
   :hidden:

   engine
   manager
   exceptions
   smi
   security

This library implements the Simple Network Management Protocol (SNMP). In spite of it's name, SNMP has a reputation for being complicated and confusing. This library is an attempt to put the "simple" back in SNMP.

An SNMP manager is a machine or an application that generates and sends SNMP requests to other machines in a network. An SNMP agent, running on one of these other machines, processes each request, and sends back a response. There are four available request types: Get, GetNext, GetBulk (as of SNMPv2), and Set. The Get* request types are generally used to query information without affecting the state of the machine, whereas the Set request is generally meant to update a machine's configuration.

Each request contains a list of "variable bindings," (varbinds), which is a fancy term for a name/value pair. The "name" of a varbind is formatted as an ASN.1 Object Identifier (OID), such as ``"1.3.6.1.2.1.1.1.0"``. Once you know the name, data type, and meaning of a variable, the protocol is quite simple to use. The hard part is determining the exact OID that corresponds to the variable you want. This is probably where SNMP gets its reputation for being complicated and confusing.

.. _manager:

The Manager Interface (Simplified)
----------------------------------

The Manager interface defines a method for each of the four request types (listed above). Each Manager object communicates with a single remote machine, so that you, the caller, only need to configure the IP address once, rather than including it in the argument list of every request. This section documents the essential arguments and behavior of this interface; :doc:`manager` section documents the interface in full.

Note that :class:`SimplifiedSnmpManager` is an abstract interface specification; there is no class with that name in the snmp library. To instantiate a concrete Manager object, you must use the :meth:`Engine.Manager()<snmp.Engine.Manager>` factory method.

.. py:class:: SimplifiedSnmpManager

   .. py:method:: get(*oids: OID | str, timeout: float = 10.0) -> VarBindList

      This method sends an SNMP Get request and awaits the response. The positional arguments give the OIDs for the request. Each argument may be either a string, formatted like ``".1.3.6.1.2.1.1.1.0"`` or ``"1.3.6.1.2.1.1.1.0"`` (i.e. with or without the leading dot), or an :class:`snmp.smi.OID` object. The method will block until a response is received, up to a maximum of `timeout` seconds.

      When successful, the call returns the variable bindings as a :class:`snmp.smi.VarBindList`.

      .. code-block:: python

         vblist = manager.get("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0")

         # VarBindList -> VarBind -> OctetString -> bytes -> str
         descr = vblist[0].value.data.decode()

         # VarBindList -> VarBind -> TimeTicks -> int -> float
         uptime = vblist[1].value.value / 100

         print(f"System Description: \"{descr}\"")
         print(f"System Up-Time: {uptime} seconds")

      This method raises an :class:`ErrorResponse<snmp.ErrorResponse>` exception when it receives a response with a non-zero error-status, indicating that the agent was able to understand the request, but not able to fulfill it. In the case of a ``"noSuchName"`` error, the call raises the more specific :class:`NoSuchName<snmp.NoSuchName>` exception, a sub-class of :class:`ErrorResponse<snmp.ErrorResponse>`, so that you may handle it in a dedicated except block.

      If the Manager does not receive a response within `timeout` seconds, it will raise a :class:`Timeout<snmp.Timeout>` exception.

      In some cases, this method may raise an :class:`Exception` type other than those listed here. See :meth:`SnmpManager.get` for more details.

      .. code-block:: python

         oid = "1.3.6.1.2.1.1.1.0"

         try:
             vblist = manager.get(oid)
         except NoSuchName:
             print(f"This machine has no value for {oid}")
         except ErrorResponse as err:
             print(f"Error: {err.status.name}")
         except Timeout:
             print("The request timed out!")
         except Exception as err:
             print(err)

   .. py:method:: getBulk( \
         *oids: OID | str, \
         nonRepeaters: int = 0, \
         maxRepetitions: int = 1, \
         timeout: float = 10.0,j\
      ) -> VarBindList

      Send an SNMP GetBulk request and await the response. The behavior of this method is the same as the :meth:`get` method, aside from the request type, and the addition of the nonRepeaters and maxRepetitions parameters.

      For an explanation of this request type, see :meth:`SnmpManager.getBulk`.

   .. py:method:: getNext(*oids: OID | str, timeout: float = 10.0) -> VarBindList

      Send an SNMP GetNext request, and await the response. The behavior of this method is the same as the :meth:`get` method, aside from the request type.

   .. py:method:: set( \
         *varbinds: VarBind | tuple, \
         timeout: float = 10.0 \
      ) -> VarBindList

      Send an SNMP Set request, and await the response. The behavior of this method is the same as the :meth:`get` method, aside from the request type and the format of the positional arguments.

      While the other request methods take OIDs for the positional arguments, this method requires a value to go along with each OID. The varbinds argument(s) may be either a ``(name, value)`` tuple, or a :class:`VarBind<snmp.smi.VarBind>`. The ``name`` element accepts either a :class:`str` or an :class:`OID<snmp.smi.OID>`, just like the `*oids` argument list to the :meth:`get` method. The ``value`` element must be an instance of one of the classes defined in :mod:`snmp.smi`.

      .. code-block:: python

         name = "1.3.6.1.2.1.1.1.0"
         value = OctetString(b"New system description")
         vblist = manager.set((name, value))

Package Structure
-----------------

Each of the following sections lists the variables that are defined as a result
of the given ``import`` statement.

Essential Features
******************

The top-level ``snmp`` module exports all the essential data types and named
constants needed for a basic SNMP application.

.. code-block:: python

   from snmp import *

Engine Class:

- :class:`Engine<snmp.Engine>`

Named Constants:

- :data:`SNMPv1<snmp.SNMPv1>`
- :data:`SNMPv2c<snmp.SNMPv2c>`
- :data:`SNMPv3<snmp.SNMPv3>`
- :data:`UDP_IPv4<snmp.UDP_IPv4>`
- :data:`UDP_IPv6<snmp.UDP_IPv6>`
- :data:`noAuthNoPriv<snmp.noAuthNoPriv>`
- :data:`authNoPriv<snmp.authNoPriv>`
- :data:`authPriv<snmp.authPriv>`

Enumerations:

- :class:`ErrorStatus<snmp.ErrorStatus>`

Exception Types:

- :class:`ErrorResponse<snmp.ErrorResponse>`
- :class:`NoSuchName<snmp.NoSuchName>`
- :class:`Timeout<snmp.Timeout>`
- :class:`ImproperResponse<snmp.ImproperResponse>`

SMI Classes (from ``snmp.smi``):

- :class:`OID<snmp.smi.OID>`
- :class:`NoSuchObject<snmp.smi.NoSuchObject>`
- :class:`NoSuchInstance<snmp.smi.NoSuchInstance>`
- :class:`EndOfMibView<snmp.smi.EndOfMibView>`

SNMP Data Types
***************

.. code-block:: python

   from snmp.smi import *

Primitive Types:

- :class:`Integer<snmp.smi.Integer>`
- :class:`OctetString<snmp.smi.OctetString>`
- :class:`Null<snmp.smi.Null>`
- :class:`OID<snmp.smi.OID>`

Integer Types:

- :class:`Integer32<snmp.smi.Integer32>`
- :class:`Unsigned<snmp.smi.Unsigned>`
- :class:`Unsigned32<snmp.smi.Unsigned32>`
- :class:`Counter32<snmp.smi.Counter32>`
- :class:`Counter64<snmp.smi.Counter64>`
- :class:`Gauge32<snmp.smi.Gauge32>`
- :class:`TimeTicks<snmp.smi.TimeTicks>`

OctetString Types:

- :class:`IpAddress<snmp.smi.IpAddress>`
- :class:`Opaque<snmp.smi.Opaque>`

Null Types:

- :class:`NoSuchObject<snmp.smi.NoSuchObject>`
- :class:`NoSuchInstance<snmp.smi.NoSuchInstance>`
- :class:`EndOfMibView<snmp.smi.EndOfMibView>`

Named Constants:

- :data:`zeroDotZero<snmp.smi.zeroDotZero>`

Variable Bindings:

- :class:`VarBind<snmp.smi.VarBind>`
- :class:`VarBindList<snmp.smi.VarBindList>`

Authentication Protocols
************************

.. code-block:: python

   from snmp.security.usm.auth import *

- :class:`HmacMd5<snmp.security.usm.auth.HmacMd5>`
- :class:`HmacSha<snmp.security.usm.auth.HmacSha>`
- :class:`HmacSha224<snmp.security.usm.auth.HmacSha224>`
- :class:`HmacSha256<snmp.security.usm.auth.HmacSha256>`
- :class:`HmacSha384<snmp.security.usm.auth.HmacSha384>`
- :class:`HmacSha512<snmp.security.usm.auth.HmacSha512>`

Privacy Protocols
*****************

.. code-block:: python

   from snmp.security.usm.priv import *

- :class:`AesCfb128<snmp.security.usm.priv.AesCfb128>`
- :class:`DesCbc<snmp.security.usm.priv.DesCbc>`
