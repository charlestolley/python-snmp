Installation
============

pip install snmp
----------------

The simplest way to install ``snmp`` is with ``pip``:

.. code-block:: console

   pip install snmp

Source Download
---------------

You can also download ``snmp`` directly from `GitHub`_. Copy the ``snmp``
subdirectory to your desired installation location.

.. _GitHub: https://github.com/charlestolley/python-snmp

Customization
-------------

Nearly the entire ``snmp`` library is written exclusively in Python, using only
the standard library. The only exception is the :mod:`snmp.security.usm.priv`
module, which relies on third-party libraries to support encryption in SNMPv3.
However, this module is considered optional; all other features in the library
will work perfectly fine without it.

There are two provided implementations for :mod:`snmp.security.usm.priv`: one
that depends on the ``pycryptodome`` library, and one that uses ``OpenSSL``.
The module initialization code will automatically select between these
implementations, depending on whether these dependencies are installed.

pycryptodome
^^^^^^^^^^^^

The standard :mod:`snmp.security.usm.priv` implementation uses ``pycryptodome``
to perform the encryption and decryption. ``pycryptodome`` will be installed
automatically when you install ``snmp`` with ``pip``. There is also a
``requirements.txt`` file provided in ``snmp/security/usm/priv/pycryptodome``,
which specifies the precise requirement.

OpenSSL
^^^^^^^

The other :mod:`snmp.security.usm.priv` implementation uses the ``EVP_*`` family
of functions, from OpenSSL. To enable it, you will use the ``cffi`` library to
generate and compile a Python module that can interface with OpenSSL. If
present, this module will always take precedence over ``pycryptodome``, based on
the assumption that you would not take the time to install it unless you wanted
to use it.

First, install the ``cffi`` library with this command:

.. code-block:: console

   pip install -r snmp/cffi/requirements.txt

After installing ``cffi``, run the following commands in the Python interactive
shell:

.. code-block:: console

   >>> from snmp.cffi.openssl import ffi
   >>> ffi.compile()

If this command fails, the most likely cause is from missing OpenSSL headers.
Most Linux distributions provide OpenSSL binaries automatically, but require
you to install the headers separately. The precise instructions will vary by
system, so it will be up to you to figure it out.

In Ubuntu, it's as simple as

.. code-block:: console

   sudo apt install libssl-dev

You can also download_ and install OpenSSL from source quite easily (run
``Configure``, and then ``make install``). If you install in a non-standard
location, then set ``CPPFLAGS="-isystem <prefix>/include"`` and
``LDFLAGS="-Wl,-rpath,<prefix>/lib"`` in your environment before opening the
Python interactive shell.

If installing OpenSSL headers doesn't fix your issue, or you get stuck, please
file a GitHub issue or email me directly at charlescdtolley@protonmail.com.

.. _download: https://www.openssl.org/source/
