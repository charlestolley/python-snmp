from test import ber
from test import types
from test import utils
from test.pdu import v2 as PDUv2
from test.smi import v2 as SMIv2
from test import security
from test.security import levels

# The order of this list is meant to test each module
# before testing the modules that depend on it
modules = [
    utils, ber, types, SMIv2, PDUv2, security, levels
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
