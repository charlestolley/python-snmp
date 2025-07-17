__all__ = ["AES_128_CFB128", "DES_CBC", "Decryptor", "Encryptor"]

from snmp.openssl import *

class Cipher:
    def __init__(self, cipher, blocklen):
        self.BLOCKLEN = blocklen
        self.cipher = cipher

    def __call__(self):
        return self.cipher()

AES_128_CFB128 = Cipher(lib.EVP_aes_128_cfb128, 16)
DES_CBC = Cipher(lib.EVP_des_cbc, 8)

class EnvelopeContext:
    def __init__(self):
        self.ctx = lib.EVP_CIPHER_CTX_new()

        if self.ctx == ffi.NULL:
            raise RuntimeError("Failed to allocate EVP_CIPHER_CTX")

    def __enter__(self):
        return self.ctx

    def __exit__(self, *args):
        lib.EVP_CIPHER_CTX_free(self.ctx)

class Envelope:
    def __init__(self, cipher):
        self.cipher = cipher

        if self.ENCRYPT:
            self.init = lib.EVP_EncryptInit
            self.update = lib.EVP_EncryptUpdate
        else:
            self.init = lib.EVP_DecryptInit
            self.update = lib.EVP_DecryptUpdate

    @staticmethod
    def allocateOutputBuffer(datalen, blocklen):
        length = datalen + blocklen - (datalen % blocklen)
        return ffi.new(f"unsigned char[]", length)

    def process(self, data, key, iv):
        with EnvelopeContext() as ctx:
            if not self.init(ctx, self.cipher(), key, iv):
                raise RuntimeError("Failed to initialize cipher context")

            inl = len(data)
            outl = ffi.new("int*")
            output = self.allocateOutputBuffer(len(data), self.cipher.BLOCKLEN)

            if not self.update(ctx, output, outl, data, inl):
                raise RuntimeError("Failed to update cipher context")

            return bytes(output)

class Decryptor(Envelope):
    ENCRYPT = False
    decrypt = Envelope.process

class Encryptor(Envelope):
    ENCRYPT = True
    encrypt = Envelope.process
