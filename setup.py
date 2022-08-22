import importlib
import os
import os.path
import re
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

class build_openssl(build_ext):
    REGEX = re.compile(r"^snmp((?:\.[^.]+)+)$")

    def run(self):
        from cffi.recompiler import make_c_source
        sys.path.insert(0, os.path.dirname(__file__))

        if not os.path.exists(self.build_temp):
            os.mkdir(self.build_temp)

        indices = []
        for index, ext in enumerate(self.extensions):
            match = self.REGEX.match(ext.name)
            if match is not None:
                ffi = importlib.import_module("snmp.cffi" + match.group(1)).ffi
                module, preamble, fileext = ffi._assigned_source[:3]
                outfile = os.path.join(self.build_temp, f"{module}{fileext}")
                make_c_source(ffi, module, preamble, outfile)
                ext.sources.append(outfile)
                indices.append(index)

        sys.path.pop(0)

        try:
            return super().run()
        except Exception:
            print("Failed to compile optional 'snmp.openssl' package")

        for index in reversed(indices):
            self.extensions.pop(index)

        return super().run()

sys.path.insert(0, os.path.dirname(__file__))

extensions = []
for name in ("aes", "des"):
    ffi = importlib.import_module(f"snmp.cffi.openssl.{name}").ffi
    module = ffi._assigned_source[0]
    kwargs = ffi._assigned_source[3]
    extensions.append(Extension(module, [], **kwargs))

sys.path.pop(0)

setup(
    cmdclass = {"build_ext": build_openssl},
    ext_modules=extensions,
    install_requires=["cffi>=1.0.0"],
    setup_requires=["cffi>=1.0.0"],
)
