import test.ber
import test.message
import test.pdu
import test.security
import test.security.levels
import test.security.usm
import test.security.usm.auth
import test.security.usm.priv
import test.smi
import test.transport.udp
import test.types
import test.utils

# The order of this list is meant to test each module
# before testing the modules that depend on it
modules = [
    test.utils,
    test.ber,
    test.types,
    test.smi,
    test.pdu,
    test.message,
    test.security,
    test.security.levels,
    test.security.usm,
    test.security.usm.auth,
    test.security.usm.priv,
    test.transport.udp,
]

def allTests(cls):
    for attrname in dir(cls):
        if attrname.startswith("test"):
            attr = getattr(cls, attrname)
            if hasattr(attr, "__call__"):
                yield cls(attrname)

import unittest
suite = unittest.TestSuite()
for module in modules:
    for name in module.__all__:
        suite.addTests(allTests(getattr(module, name)))

runner = unittest.TextTestRunner()
runner.run(suite)
