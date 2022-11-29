Installation
============

:mod:`snmp` is available in pip:

.. code-block:: console

   pip install snmp

Integration with OpenSSL
------------------------

.. note::

   For Windows, I'm providing statically-linked wheels in PyPI to spare
   everyone from having to figure out how to install OpenSSL. I took this
   idea from the ``cryptography`` library.

   .. note::
   
      I would have used the ``cryptography`` library directly, but they no
      longer support DES, whereas some Cisco switches *only* support DES.

If you are using SNMPv3 with privacy enabled, you may have come across this
error:

.. code-block:: Python

   ModuleNotFoundError: No module named 'snmp.openssl'

Well, you've come to the right place. This library treats :mod:`snmp.openssl` as
optional, as it is very common to use SNMP without encryption. During
installation, the setup script will attempt to build this module, but if it
fails, it will simply omit it, rather than crashing the whole installation.

Most Linux distributions include OpenSSL binaries, but not the header files,
which are required in order to build :mod:`snmp.openssl`. The solution is simply
to install these headers, then uninstall and reinstall :mod:`snmp` with pip.

In Ubuntu, it's as simple as

.. code-block:: console

   sudo apt install libssl-dev
   pip uninstall snmp
   pip install snmp

You can also download_ and install OpenSSL from source quite easily (run
``Configure``, and then ``make install``). If you install in a non-standard
location, then set ``CPPFLAGS="-isystem <prefix>/include"`` and
``LDFLAGS="-Wl,-rpath,<prefix>/lib"`` in your environment before calling ``pip
install``.

If installing OpenSSL headers doesn't fix the issue, try using ``pip install -v
snmp`` to get verbose output, which will show you the error directly from the
compiler. If you get stuck, please file a GitHub issue or find my email address
in setup.cfg and email me directly.

Manually Compile :mod:`snmp.openssl`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is possible to compile :mod:`snmp.openssl` manually, whether or not you are
using pip. First, navigate to the directory that houses ``snmp/``. This will
either be the top-level directory in a clone of the Git repository, or the
``site-packages`` directory of your Python installation.

After setting ``CPPFLAGS`` and/or ``LDFLAGS`` in the environment (if necessary
-- see above), call ``python`` to open the interactive shell, and run the
following commands:

.. code-block:: python

   from snmp.cffi.openssl.aes import ffi as aes
   from snmp.cffi.openssl.des import ffi as des
   aes.compile()
   des.compile()

Each of the latter two commands will compile a dynamic shared object library
(\*.so) file, and return the path, which should be under
``<current-working-directory>/snmp/openssl/``.

.. _download: https://www.openssl.org/source/
