#include "wcrypto.h"
#include "wlibc.h"

static _Noreturn void unsupportedSoftwareHash(const char *name)
{
    printError("%s is not implemented by the software crypto backend yet.\n", name);
    terminateProgram(1);
}

int wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA224");
}

int wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA256");
}

int wCryptoSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA384");
}

int wCryptoSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA512");
}

int wCryptoSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA3_224");
}

int wCryptoSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA3_256");
}

int wCryptoSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA3_384");
}

int wCryptoSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSoftwareHash("wCryptoSHA3_512");
}
