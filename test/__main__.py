test_modules = [
    "utils",
    "ber",
    "asn1",
    "smi",
    "pdu",
    "message.version",
    "message.core",
    "message.v1",
    "message.v2c",
    "message.v3",
    "security.levels",
    "security.models",
    "security.usm.timekeeper",
    "security.usm.parameters",
    "security.usm.credentials",
    "security.usm.users",
    "security.usm.implementation",
    "security.usm.auth",
    "security.usm.priv.openssl",
    "security.usm.priv.pycryptodome",
    "transport.udp",
    "scheduler",
    "v1.manager",
]

import importlib
import unittest

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
