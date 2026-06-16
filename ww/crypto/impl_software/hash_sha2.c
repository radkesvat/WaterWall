#include "private/crypto_backends.h"
#include "wlibc.h"

#include "sha2.h"

static int softwareSHA2HashValidateInput(const void *out, const unsigned char *in, size_t inlen)
{
    if (! out || (! in && inlen > 0))
    {
        printError("Invalid input for software crypto hash function.\n");
        return -1;
    }

    return 0;
}

static const unsigned char *softwareSHA2HashNormalizeInput(const unsigned char *in)
{
    static const unsigned char empty_input = 0;
    return in ? in : &empty_input;
}

int wCryptoSoftwareSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
    if (softwareSHA2HashValidateInput(out, in, inlen) != 0)
    {
        return -1;
    }

    sha224(softwareSHA2HashNormalizeInput(in), (sha2_uint64) inlen, out->bytes);
    return 0;
}

int wCryptoSoftwareSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    if (softwareSHA2HashValidateInput(out, in, inlen) != 0)
    {
        return -1;
    }

    sha256(softwareSHA2HashNormalizeInput(in), (sha2_uint64) inlen, out->bytes);
    return 0;
}
