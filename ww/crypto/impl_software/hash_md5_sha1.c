#include "wcrypto.h"
#include "wlibc.h"
#include "utils/md5.h"
#include "utils/sha1.h"

static int validateHashInput(const void *out, const unsigned char *in, size_t inlen)
{
    if (!out || (!in && inlen > 0))
    {
        printError("Invalid input for crypto hash function.\n");
        return -1;
    }

    return 0;
}

static const unsigned char *normalizeHashInput(const unsigned char *in)
{
    static const unsigned char empty_input = 0;
    return in ? in : &empty_input;
}

int wCryptoMD5(md5_hash_t *out, const unsigned char *in, size_t inlen)
{
    if (validateHashInput(out, in, inlen) != 0)
    {
        return -1;
    }
    if (inlen > UINT_MAX)
    {
        printError("wCryptoMD5 input is too large for the software MD5 implementation.\n");
        return -1;
    }

    wwMD5((unsigned char *) normalizeHashInput(in), (unsigned int) inlen, out->bytes);
    return 0;
}

int wCryptoSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen)
{
    if (validateHashInput(out, in, inlen) != 0)
    {
        return -1;
    }
    if (inlen > UINT32_MAX)
    {
        printError("wCryptoSHA1 input is too large for the software SHA1 implementation.\n");
        return -1;
    }

    wwSHA1((unsigned char *) normalizeHashInput(in), (uint32_t) inlen, out->bytes);
    return 0;
}
