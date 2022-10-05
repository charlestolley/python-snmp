:mod:`snmp` --- Simple Network Management Protocol
==================================================

.. module:: snmp
   :synopsis: Python SNMP implementation

--------------

This library provides a pure-Python implementation of the Simple Network Management Protocol. It is designed primarily for ease of use, with a secondary goal of minimizing resource usage, specifically in the number of threads and the amount of network traffic.

.. note::

   The current library version only supports the role of Command Generator (i.e. a manager that is not capable of processing Traps). Support for additional roles will be forthcoming.
