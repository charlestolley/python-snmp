from setuptools import setup

setup(
    cffi_modules=[
        "snmp/cffi/openssl/aes.py:ffi",
        "snmp/cffi/openssl/des.py:ffi",
    ],
    install_requires=["cffi>=1.0.0"],
    setup_requires=["cffi>=1.0.0"],
)
