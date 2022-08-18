import cffi
import os

if os.name == "nt":
    libcrypto = "libcrypto_static"
else:
    libcrypto = "crypto"

ffi = cffi.FFI()
ffi.cdef("""
#define DES_DECRYPT 0
#define DES_ENCRYPT 1

typedef unsigned char DES_cblock[8];
typedef unsigned char const_DES_cblock[8];
typedef unsigned int DES_LONG;
typedef struct DES_ks {
    union {
        DES_cblock cblock;
        DES_LONG deslong[2];
    } ks[16];
} DES_key_schedule;

void DES_set_odd_parity(DES_cblock *key);
void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule);
void DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     long length, DES_key_schedule *schedule,
                     DES_cblock *ivec, int enc);
""")

ffi.set_source(
    "snmp.openssl.des",
    "#include <openssl/des.h>",
    libraries=[libcrypto]
)
