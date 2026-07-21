#include "private/crypto_backends.h"
#include "private/crypto_validation.h"
#include "utils/md5.h"
#include "utils/sha1.h"

static const unsigned char *softwareMD5SHA1HashNormalizeInput(const unsigned char *in)
{
    static const unsigned char empty_input = 0;
    return in ? in : &empty_input;
}

wcrypto_status_t wCryptoSoftwareMD5(md5_hash_t *out, const unsigned char *in, size_t inlen)
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
    if (inlen > UINT_MAX)
    {
        wCryptoZero(out, sizeof(*out));
        return kWCryptoInputTooLarge;
    }

    wwMD5((unsigned char *) softwareMD5SHA1HashNormalizeInput(in), (unsigned int) inlen, out->bytes);
    return kWCryptoOk;
}

wcrypto_status_t wCryptoSoftwareSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen)
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
    if (inlen > UINT32_MAX)
    {
        wCryptoZero(out, sizeof(*out));
        return kWCryptoInputTooLarge;
    }

    wwSHA1((unsigned char *) softwareMD5SHA1HashNormalizeInput(in), (uint32_t) inlen, out->bytes);
    return kWCryptoOk;
}
