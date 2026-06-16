#include "private/crypto_backends.h"
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

int wCryptoSodiumSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");
    if (sodiumHashValidateInput(out, in, inlen) != 0)
    {
        return -1;
    }

    return crypto_hash_sha256(out->bytes, sodiumHashNormalizeInput(in), (unsigned long long) inlen);
}

int wCryptoSodiumSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");
    if (sodiumHashValidateInput(out, in, inlen) != 0)
    {
        return -1;
    }

    return crypto_hash_sha512(out->bytes, sodiumHashNormalizeInput(in), (unsigned long long) inlen);
}
