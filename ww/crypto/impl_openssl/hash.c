#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <openssl/evp.h>

static wcrypto_status_t opensslDigest(unsigned char *out, size_t outlen, const EVP_MD *md, const unsigned char *in,
                                      size_t inlen)
{
    wcrypto_status_t status = wCryptoValidateHash(out, in, inlen);
    if (status != kWCryptoOk)
    {
        if (out != NULL)
        {
            wCryptoZero(out, outlen);
        }
        return status;
    }
    if (md == NULL)
    {
        wCryptoZero(out, outlen);
        return kWCryptoUnavailable;
    }

    static const unsigned char empty      = 0;
    unsigned int               digest_len = 0;
    if (EVP_Digest(in != NULL ? in : &empty, inlen, out, &digest_len, md, NULL) != 1 || digest_len != outlen)
    {
        wCryptoZero(out, outlen);
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoOpenSSLMD5(md5_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, MD5_DIGEST_SIZE, EVP_md5(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA1_DIGEST_SIZE, EVP_sha1(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA224_DIGEST_SIZE, EVP_sha224(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA256_DIGEST_SIZE, EVP_sha256(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA384_DIGEST_SIZE, EVP_sha384(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA512_DIGEST_SIZE, EVP_sha512(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA3_224_DIGEST_SIZE, EVP_sha3_224(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA3_256_DIGEST_SIZE, EVP_sha3_256(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA3_384_DIGEST_SIZE, EVP_sha3_384(), in, inlen);
}
wcrypto_status_t wCryptoOpenSSLSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen)
{
    return opensslDigest(out != NULL ? out->bytes : NULL, SHA3_512_DIGEST_SIZE, EVP_sha3_512(), in, inlen);
}
