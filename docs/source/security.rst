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

.. _RFC 3414, Section 6: https://datatracker.ietf.org/doc/html/rfc3414.html#section-6
.. _RFC 3414, Section 7: https://datatracker.ietf.org/doc/html/rfc3414.html#section-7
.. _RFC 3414, Section 8: https://datatracker.ietf.org/doc/html/rfc3414.html#section-8
.. _RFC 3826, Section 3: https://datatracker.ietf.org/doc/html/rfc3826.html#section-3
.. _RFC 7860: https://datatracker.ietf.org/doc/html/rfc7860.html
