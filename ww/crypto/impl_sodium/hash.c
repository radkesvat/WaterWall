#include "wcrypto.h"
#include "wlibc.h"

#include "sodium.h"

static int sodiumHashValidateInput(const void *out, const unsigned char *in, size_t inlen)
{
    if (!out || (!in && inlen > 0))
    {
        printError("Invalid input for crypto hash function.\n");
        return -1;
    }

    return 0;
}

static const unsigned char *sodiumHashNormalizeInput(const unsigned char *in)
{
    static const unsigned char empty_input = 0;
    return in ? in : &empty_input;
}

static _Noreturn void unsupportedSodiumHash(const char *name)
{
    printError("%s is not implemented by the libsodium backend or its software fallback.\n", name);
    terminateProgram(1);
}

int wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSodiumHash("wCryptoSHA224");
}

int wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");
    if (sodiumHashValidateInput(out, in, inlen) != 0)
    {
        return -1;
    }

    return crypto_hash_sha256(out->bytes, sodiumHashNormalizeInput(in), (unsigned long long) inlen);
}

int wCryptoSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSodiumHash("wCryptoSHA384");
}

int wCryptoSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");
    if (sodiumHashValidateInput(out, in, inlen) != 0)
    {
        return -1;
    }

    return crypto_hash_sha512(out->bytes, sodiumHashNormalizeInput(in), (unsigned long long) inlen);
}

int wCryptoSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSodiumHash("wCryptoSHA3_224");
}

int wCryptoSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSodiumHash("wCryptoSHA3_256");
}

int wCryptoSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSodiumHash("wCryptoSHA3_384");
}

int wCryptoSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen)
{
    discard out;
    discard in;
    discard inlen;
    unsupportedSodiumHash("wCryptoSHA3_512");
}
