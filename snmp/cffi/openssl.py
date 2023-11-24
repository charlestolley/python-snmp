import os

if os.name == "nt":
    libcrypto = "libcrypto_static"
else:
    libcrypto = "crypto"

import cffi # type: ignore[import-untyped]

ffi = cffi.FFI()
ffi.cdef("""
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                    const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      int *outl, const unsigned char *in, int inl);

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                    const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      int *outl, const unsigned char *in, int inl);

const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);
""")

ffi.set_source(
    "snmp.openssl",
    "#include <openssl/evp.h>",
    libraries=[libcrypto],
)
