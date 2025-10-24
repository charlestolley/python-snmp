:mod:`snmp` --- Simple Network Management Protocol
==================================================

.. toctree::
   :hidden:

   engine
   manager
   exceptions
   smi
   snmp
   datatypes

This library implements the Simple Network Management Protocol (SNMP). In spite of it's name, SNMP has a reputation for being complicated and confusing. This library is an attempt to put the "simple" back in SNMP.

An SNMP manager is a machine or an application that generates and sends SNMP requests to other machines in a network. An SNMP agent, running on one of these other machines, processes each request, and sends back a response. There are four available request types: Get, GetNext, GetBulk (as of SNMPv2), and Set. The Get* request types are generally used to query information without affecting the state of the machine, whereas the Set request is generally meant to update a machine's configuration.

Each request contains a list of "variable bindings," (varbinds), which is a fancy term for a name/value pair. The "name" of a varbind is formatted as an ASN.1 Object Identifier (OID), such as "1.3.6.1.2.1.1.1.0". Once you know the name, data type, and meaning of a variable, the protocol is quite simple to use. The hard part is determining the exact OID that corresponds to the variable you want. This is probably where SNMP gets its reputation for being complicated and confusing.

.. _manager:

The Manager Interface (Simplified)
----------------------------------

The Manager interface defines a method for each of the four request types (listed above). Each Manager object communicates with a single remote machine, so that you, the caller, only need to configure the IP address once, rather than including it in the argument list of every request. This section documents the essential arguments and behavior of this interface; the Manager Interface (Complete) section documents the interface in full.

Note that SimplifiedSnmpManager is an abstract interface specification; there is no class with that name in the snmp library. To instantiate a concrete Manager object, you must use the Engine.Manager() factory method.

.. py:class:: SimplifiedSnmpManager

   .. py:method:: get(*oids, timeout=10.0) -> VarBindList

      This method sends an SNMP Get request and awaits the response. The positional arguments give the OIDs for the request. Each argument may be either a string, formatted like ".1.3.6.1.2.1.1.1.0" or "1.3.6.1.2.1.1.1.0" (i.e. with or without the leading dot), or an OID object. The method will block until a response is received, up to a maximum of timeout seconds.

      When successful, the call returns the variable bindings as a VarBindList.

      .. code-block:: python

         vblist = manager.get("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0")

         # VarBindList -> VarBind -> OctetString -> bytes -> str
         descr = vblist[0].value.data.decode()

         # VarBindList -> VarBind -> TimeTicks -> int -> float
         uptime = vblist[1].value.value / 100

         print(f"System Description: \"{descr}\"")
         print(f"System Up-Time: {uptime} seconds")

      This method raises an ErrorResponse exception when it receives a response with a non-zero error-status, indicating that the agent was able to understand the request, but not able to fulfill it. In the case of a "noSuchName" error, the call raises the more specific NoSuchName exception, a sub-class of ErrorResponse, so that you may handle it in a dedicated except block.

      If the Manager does not receive a response within timeout seconds, it will raise a Timeout exception.

      In some cases, this method may raise an Exception type other than those listed here. See the complete interface documentation for more details.

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

   .. py:method:: getBulk(*oids, nonRepeaters=0, maxRepetitions=1, timeout=10.0) -> VarBindList

      .. note::

         This method is not defined for an SNMPv1 manager.

      Send an SNMP GetBulk request and await the response. The behavior of this method is the same as the get() method, aside from the request type, and the addition of the nonRepeaters and maxRepetitions parameters. These parameters correspond to the similarly-named fields in the GetBulkRequest-PDU. See `RFC 3416, Section 4.2.3`_ for an explanation of the GetBulk request, and the meaning of these fields.

   .. py:method:: getNext(*oids, timeout=10.0) -> VarBindList

      Send an SNMP GetNext request, and await the response. The behavior of this method is the same as the get() method, aside from the request type.

   .. py:method:: set(*varbinds, timeout=10.0) -> VarBindList

      Send an SNMP Set request, and await the response. The behavior of this method is the same as the get() method, aside from the request type and the format of the positional arguments.

      While the other request methods take OIDs for the positional arguments, this method requires a value to go along with each OID. The varbind argument(s) may be either a (name, value) tuple, or a VarBind. The name element accepts either a string or an OID, just like the oid argument(s) to the get() method. The value element must be an instance of one of the classes defined by snmp.smi, corresponding to the ObjectSyntax types defined in RFC 3416, Section 3.

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

Drafts (DELETE ME)
------------------

The problem with this design is that an error for a single variable will invalidate the entire request. With the introduction of the Get-Bulk request (which is particularly susceptible to this flaw), SNMPv2 also introduced three new special value types: :class:`NoSuchObject<snmp.smi.NoSuchObject>`, :class:`NoSuchInstance<snmp.smi.NoSuchInstance>`, or :class:`EndOfMibView<snmp.smi.EndOfMibView>`.

:mod:`snmp`: The top level module exports all the basic components to create a manager object, make a request, and handle the possible responses.

:mod:`snmp.smi`: Classes to represent the core SNMP data types.

:mod:`snmp.security.usm.auth`: USM authentication protocol implementations.

:mod:`snmp.security.usm.priv`: USM privacy protocol implementations. This module is considered optional, so it may raise an ImportError if your environment is not set up properly; see the :doc:`installation` page for more details.

Something about Managers

# Home Page
# - Installation
# - Getting Started
# - Library Reference
#   - Programming Paradigm
#     - Engine
#     - Manager interface
#       - request methods
#       - request handle
#   - Package Structure
#     - snmp module
#     - snmp.smi
#     - snmp.security.usm.auth
#     - snmp.security.usm.priv
# 
# Engine
# - addUser()
# - Manager()
# 
# Manager
# - get()
# - getNext()
# - getBulk()
# - set()
# 
# RequestHandle
# - wait()
#   - raise ErrorResponse
#   - raise ImproperResponse
#     - variableBindings
#   - raise NoSuchName (SNMPv1)
#   - raise Timeout
# 
# VarBindList
# - __getitem__()
# 
# VarBind
# - name
# - value
#   - this library doesn't parse MIB files; it's up to the user to make sure the value is the type they expect
#   - remember that it could also be one of
#     - NoSuchObject
#     - NoSuchInstance
#     - EndOfMibView
# 
# Integer
# - value
# 
# OctetString
# - data
# 
# Null
# 
# OID
# - __eq__()
# - __getitem__()
# - decodeIndex()
# - withIndex()
# - extend()
# - startswith()

.. _RFC 3416, Section 4.2.3: https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.3
.. _Facade: https://en.wikipedia.org/wiki/Facade_pattern
.. _Factory Method: https://en.wikipedia.org/wiki/Factory_method_pattern

The purpose of SNMP is to provide an automated way for owners or custodians of a network to monitor and configure the machines in that network. The architecture of SNMP is simple enough to understand. Any machine on a network can keep track of relevant statistics related to its job, such as the number of packets that pass through a switch, or the number of hosts connected to a wireless access point. Each of these machines can run an SNMP "agent" which is a background process that listenes f, which make this information available upon request. An SNMP "manager" application queries these machines for whatever information it wants by sending 

The most confusing part of SNMP is the relationship between ASN.1 Object Identifiers (OIDs), and the information that they point to. An OID is a sequence of numbers (printed with dots between them, like this: "1.3.6.1.2.1.1.1.0") that represents a path through an imaginary tree data structure, called the "Management Information Base" (MIB). For example, the first number in the OID represents a choice between "ccitt" (0), "iso" (1), or "join-iso-ccitt" (2). The ubiquitous "1.3.6.1" prefix represents iso -> org -> dod -> internet. Standard data definitions fall under internet -> mgmt -> mib-2 (1.3.6.1.2.1), whereas data definitions for private organizations use the prefix 1.3.6.1.4.1 (internet -> private -> enterrises).

Any information available from an SNMP agent should be documented in a MIB file, either from the IETF, or from a private organization. For example, the RFC 1759 Printer-MIB defines an interface for querying information from a printer. It defines a top-level object called "printmib" (1.3.6.1.2.1.43), under which it defines other concrete objects. For example, the "prtMarkerSuppliesEntry" (1.3.6.1.43.11.1.1) defines a generic object type for consumable printing supplies, such as the toner level or the amount of paper in the tray.

Any organization can register ownership for a branch in this tree, which allows them to define the names, data types, and meaning of each OID with a certain prefix. For example, the prefix "1.3..1 This imaginary tree is called the "Management Information Base" (MIB). For example, the prefix "1.3.6.1" refers to s The most confusing part of SNMP is the organization of information into an imaginary tree data structure, called the Management Information Base. 
The basic SNMP request types are called Get, GetNext, GetBulk (as of SNMPv2), and Set. An SNMP Manager uses these requests to query a remote machine for information. An SNMP Agent, running on the remote machine, listens for requests, and generates a response message containing the requested information. 

To use this library, the first step is to create an Engine. This object stores the global configuration for your SNMP application. It also serves as a factory to generate Manager objects. Each Manager corresponds to a specific remote machine, and provides methods for each type of SNMP request: Get, GetNext, GetBulk (as of SNMPv2), and Set. The transport configuration is stored internally, so that you do not need to specify the IP address for each request. To communicate with multiple remote machines, simply create one Manager for each.

SNMP defines four types of requests: Get, GetNext, GetBulk (not in SNMPv1), and Set. Each request contains one or more "object identifiers". An object identifier (OID) is a sequence of numbers (printed with dots between them, like this: "1.3.6.1.2.1.1.1.0") that represents a path through an imaginary tree data structure. This imaginary tree is called the "Management Information Base" (MIB). Without getting too much into the weeds (because this is the confusing part of SNMP), the OIDs in your requests correspond to object definitions in a MIB file somewhere, which dictate both the data type and the meaning of the value for each variable.
