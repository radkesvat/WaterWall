#include "wcrypto.h"
#include "wlibc.h"

#include <openssl/evp.h>

static int opensslDigest(unsigned char *out, size_t outlen, const EVP_MD *md, const unsigned char *in, size_t inlen,
                         const char *name)
{
    static const unsigned char empty_input = 0;
    unsigned int               digest_len  = 0;

    if (!out || !md || (!in && inlen > 0))
    {
        printError("Invalid input for %s.\n", name);
        return -1;
    }

    if (!in)
    {
        in = &empty_input;
    }

    if (EVP_Digest(in, inlen, out, &digest_len, md, NULL) != 1)
    {
        printError("OpenSSL failed to compute %s.\n", name);
        return -1;
    }

    if (digest_len != outlen)
    {
        printError("OpenSSL returned an unexpected %s digest length.\n", name);
        return -1;
    }

    return 0;
}

int wCryptoMD5(md5_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, MD5_DIGEST_SIZE, EVP_md5(), in, inlen, "MD5");
}

int wCryptoSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA1_DIGEST_SIZE, EVP_sha1(), in, inlen, "SHA1");
}

int wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA224_DIGEST_SIZE, EVP_sha224(), in, inlen, "SHA224");
}

int wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA256_DIGEST_SIZE, EVP_sha256(), in, inlen, "SHA256");
}

int wCryptoSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA384_DIGEST_SIZE, EVP_sha384(), in, inlen, "SHA384");
}

int wCryptoSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA512_DIGEST_SIZE, EVP_sha512(), in, inlen, "SHA512");
}

int wCryptoSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA3_224_DIGEST_SIZE, EVP_sha3_224(), in, inlen, "SHA3-224");
}

int wCryptoSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA3_256_DIGEST_SIZE, EVP_sha3_256(), in, inlen, "SHA3-256");
}

int wCryptoSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA3_384_DIGEST_SIZE, EVP_sha3_384(), in, inlen, "SHA3-384");
}

int wCryptoSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out ? out->bytes : NULL, SHA3_512_DIGEST_SIZE, EVP_sha3_512(), in, inlen, "SHA3-512");
}
