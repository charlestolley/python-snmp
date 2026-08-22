Security Algorithms
===================

Authentication
--------------

.. module:: snmp.security.usm.auth

.. py:class:: HmacMd5

   An implementation of the ``HMAC-MD5-96`` algorithm defined in `RFC 3414, Section 6`_\ .

.. py:class:: HmacSha

   An implementation of the ``HMAC-SHA-96`` algorithm defined in `RFC 3414, Section 7`_\ .

.. py:class:: HmacSha224

   An implementation of the ``HMAC-SHA-224`` algorithm defined in `RFC 7860`_\ .

.. py:class:: HmacSha256

   An implementation of the ``HMAC-SHA-256`` algorithm defined in `RFC 7860`_\ .

.. py:class:: HmacSha384

   An implementation of the ``HMAC-SHA-384`` algorithm defined in `RFC 7860`_\ .

.. py:class:: HmacSha512

   An implementation of the ``HMAC-SHA-512`` algorithm defined in `RFC 7860`_\ .

Privacy
-------

   .. note::

      Consult the :doc:`installation` page if you are unable to import :mod:`snmp.security.usm.priv`.

.. module:: snmp.security.usm.priv

.. py:class:: AesCfb128

   An implementation of the ``CFB128-AES-128`` algorithm defined in `RFC 3826, Section 3`_\ .

.. py:class:: DesCbc

   An implementation of the ``CBC-DES`` algorithm defined in `RFC 3414, Section 8`_\ .

Non-Standard Algorithms
^^^^^^^^^^^^^^^^^^^^^^^

Early drafts of `RFC 3826`_ defined algorithms for AES using 192 and 256 bit
keys, but these algorithms were not accepted into the final standard. The
problem is that, under the SNMP User-Based Security Model, privacy keys are
expected to be no longer than the output of the authentication algorithm
(because the auth algorithm is used to generate the keys). Since the original
USM standard defines algorithms for MD5 and SHA-1, which produce outputs of 128
bits and 160 bits, respectively, a privacy algorithm that uses a 192 bit or 256
bit key would require a standard mechanism for key extension. In lieu of this
standard mechanism, SNMP implementors have adopted the mechanisms from some of
the rejected drafts that preceded the standard. The
:class:`EsoAesCfb192<snmp.security.usm.eso.priv.EsoAesCfb192>` and
:class:`CiscoAesCfb192<snmp.security.usm.cisco.priv.CiscoAesCfb192>` algorithms
and the :class:`EsoAesCfb256<snmp.security.usm.eso.priv.EsoAesCfb256>` and
:class:`CiscoAesCfb256<snmp.security.usm.cisco.priv.CiscoAesCfb256>` algorithms
are incompatible when paired with one of these algorithsm
(:class:`HmacMd5<snmp.security.usm.auth.HmacMd5>` or
:class:`HmacSha<snmp.security.usm.auth.HmacSha>`). However, when paired with an
authentication algorithm that produces sufficiently long output (such as
:class:`HmacSha224<snmp.security.usm.auth.HmacSha224>` for AES-192, and
:class:`HmacSha256<snmp.security.usm.auth.HmacSha256>` for AES-256), the
:mod:`eso<snmp.security.usm.eso.priv>` and
:mod:`cisco<snmp.security.usm.cisco.priv>` classes are interchangeable.

.. module:: snmp.security.usm.eso.priv

.. py:class:: EsoAesCfb192

   *New in version 1.3.*

   An implementation of the ``CFB128-AES-192`` algorithm using the key extension algorithm proposed in `draft-blumenthal-aes-usm-04, Section 3.1.2.1`_\ .

.. py:class:: EsoAesCfb256

   *New in version 1.3.*

   An implementation of the ``CFB128-AES-256`` algorithm using the key extension algorithm proposed in `draft-blumenthal-aes-usm-04, Section 3.1.2.1`_\ .

.. module:: snmp.security.usm.cisco.priv

.. py:class:: CiscoAesCfb192

   *New in version 1.3.*

   An implementation of the ``CFB128-AES-192`` algorithm using the key extension algorithm proposed in `draft-reeder-snmpv3-usm-3desede-00, Section 2.1`_\ .

.. py:class:: CiscoAesCfb256

   *New in version 1.3.*

   An implementation of the ``CFB128-AES-256`` algorithm using the key extension algorithm proposed in `draft-reeder-snmpv3-usm-3desede-00, Section 2.1`_\ .

.. _RFC 3414, Section 6: https://datatracker.ietf.org/doc/html/rfc3414.html#section-6
.. _RFC 3414, Section 7: https://datatracker.ietf.org/doc/html/rfc3414.html#section-7
.. _RFC 3414, Section 8: https://datatracker.ietf.org/doc/html/rfc3414.html#section-8
.. _RFC 3826: https://datatracker.ietf.org/doc/html/rfc3826.html
.. _RFC 3826, Section 3: https://datatracker.ietf.org/doc/html/rfc3826.html#section-3
.. _RFC 7860: https://datatracker.ietf.org/doc/html/rfc7860.html
.. _draft-blumenthal-aes-usm-04, Section 3.1.2.1: https://datatracker.ietf.org/doc/html/draft-blumenthal-aes-usm-04#page-7
.. _draft-reeder-snmpv3-usm-3desede-00, Section 2.1: https://datatracker.ietf.org/doc/html/draft-reeder-snmpv3-usm-3desede-00#section-2.1
