from importlib import import_module

from snmp.exception import IncomingMessageError

class DecryptionError(IncomingMessageError):
    pass

packages = (
    "pycryptodome",
    "openssl",
)

modules = (
    "aes",
    "des",
)

for package in packages:
    variables = {}

    for module_name in modules:
        try:
            module = import_module(f".{module_name}", f"{__name__}.{package}")
        except ImportError:
            break

        for variable_name in module.__all__:
            variables[variable_name] = getattr(module, variable_name)

    else:
        globals().update(variables)
        __all__ = list(variables)
        break
else:
    raise ImportError(
        "This installation does not include an encryption implementation"
    )
