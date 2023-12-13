test_modules = [
    "utils",
    "ber",
    "asn1",
    #"types",
    "smi",
    "pdu",
    "message",
    "message.v1",
    "message.v2c",
    "message.v3",
    "security",
    "security.levels",
    "security.usm",
    "security.usm.auth",
    "security.usm.priv",
    "transport.udp",
]

import importlib
import sys
import unittest

from os.path import dirname
sys.path.insert(0, dirname(dirname(__file__)))

def allTests(cls):
    for attrname in dir(cls):
        if attrname.startswith("test"):
            attr = getattr(cls, attrname)
            if hasattr(attr, "__call__"):
                yield cls(attrname)


suite = unittest.TestSuite()
for module_name in test_modules:
    module = importlib.import_module(f".{module_name}", package=__package__)
    for variable_name in module.__all__:
        suite.addTests(allTests(getattr(module, variable_name)))

runner = unittest.TextTestRunner()
runner.run(suite)
