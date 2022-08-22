import os

if os.name == "nt":
    libcrypto = "libcrypto_static"
else:
    libcrypto = "crypto"
