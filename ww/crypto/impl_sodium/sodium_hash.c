#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <sodium.h>

static const unsigned char *normalizeInput(const unsigned char *in)
{
    static const unsigned char empty = 0;
    return in != NULL ? in : &empty;
}
wcrypto_status_t wCryptoSodiumSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    wcrypto_status_t status = wCryptoValidateHash(out, in, inlen);
    if (status != kWCryptoOk)
    {
        if (out != NULL)
        {
            wCryptoZero(out, sizeof(*out));
        }
        return status;
    }
    if (crypto_hash_sha256(out->bytes, normalizeInput(in), (unsigned long long) inlen) != 0)
    {
        wCryptoZero(out, sizeof(*out));
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoSodiumSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
    wcrypto_status_t status = wCryptoValidateHash(out, in, inlen);
    if (status != kWCryptoOk)
    {
        if (out != NULL)
        {
            wCryptoZero(out, sizeof(*out));
        }
        return status;
    }
    if (crypto_hash_sha512(out->bytes, normalizeInput(in), (unsigned long long) inlen) != 0)
    {
        wCryptoZero(out, sizeof(*out));
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}
