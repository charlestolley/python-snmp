from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Aes128Cfb:
    BYTEORDER = "big"
    KEYLEN = 16
    SALTLEN = 8
    SALTWRAP = 1 << (8 * SALTLEN)

    def __init__(self, key):
        if len(key) < self.KEYLEN:
            errmsg = "key must be at least {} bytes long".format(self.KEYLEN)
            raise ValueError(errmsg)

        self.algo = algorithms.AES(key[:self.KEYLEN])
        self.salt = int.from_bytes(urandom(self.SALTLEN), self.BYTEORDER)

    @property
    def msgPrivacyParameters(self):
        self.salt = (self.salt + 1) % self.SALTWRAP
        return self.salt.to_bytes(self.SALTLEN, self.BYTEORDER)

    def cipher(self, engineBoots, engineTime, salt):
        if len(salt) != self.SALTLEN:
            raise ValueError("Invalid salt")

        iv = b''.join((
            engineBoots.to_bytes(4, self.BYTEORDER),
            engineTime .to_bytes(4, self.BYTEORDER),
            salt
        ))

        return Cipher(
            self.algo,
            modes.CFB(iv),
            default_backend()
        )

    def decrypt(self, data, *args, **kwargs):
        decryptor = self.cipher(*args, **kwargs).decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def encrypt(self, data, *args, **kwargs):
        encryptor = self.cipher(*args, **kwargs).encryptor()
        return encryptor.update(data) + encryptor.finalize()
