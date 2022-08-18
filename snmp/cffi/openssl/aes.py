import cffi
import os

if os.name == "nt":
    libcrypto = "libcrypto_static"
else:
    libcrypto = "crypto"

ffi = cffi.FFI()
ffi.cdef("""
#define AES_DECRYPT 0
#define AES_ENCRYPT 1
#define AES_MAXNR 14

struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};

typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char *ivec, int *num, const int enc);
""")

ffi.set_source(
    "snmp.openssl.aes",
    "#include <openssl/aes.h>",
    libraries=[libcrypto]
)
