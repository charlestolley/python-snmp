from test import ber
from test import types
from test import utils

# The order of this list is meant to test each module
# before testing the modules that depend on it
modules = [
    utils, ber, types,
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
