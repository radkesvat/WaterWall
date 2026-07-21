#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include "sha2.h"

static const unsigned char *softwareSHA2HashNormalizeInput(const unsigned char *in)
{
    static const unsigned char empty_input = 0;
    return in ? in : &empty_input;
}

wcrypto_status_t wCryptoSoftwareSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
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

    sha224(softwareSHA2HashNormalizeInput(in), (sha2_uint64) inlen, out->bytes);
    return kWCryptoOk;
}

wcrypto_status_t wCryptoSoftwareSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
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

    sha256(softwareSHA2HashNormalizeInput(in), (sha2_uint64) inlen, out->bytes);
    return kWCryptoOk;
}

wcrypto_status_t wCryptoSoftwareSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen)
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

    sha384(softwareSHA2HashNormalizeInput(in), (sha2_uint64) inlen, out->bytes);
    return kWCryptoOk;
}

wcrypto_status_t wCryptoSoftwareSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
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

    sha512(softwareSHA2HashNormalizeInput(in), (sha2_uint64) inlen, out->bytes);
    return kWCryptoOk;
}
