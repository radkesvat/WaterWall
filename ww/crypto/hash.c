#include "private/crypto_backends.h"
#include "private/crypto_validation.h"
#include "wcrypto.h"

typedef wcrypto_status_t (*hash_backend_fn)(void *, const unsigned char *, size_t);

static wcrypto_status_t dispatchHash(void *out, size_t outlen, const unsigned char *in, size_t inlen,
                                     hash_backend_fn backend)
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
    if (! wCryptoIsInitialized())
    {
        wCryptoZero(out, outlen);
        return kWCryptoInvalidState;
    }
    if (backend == NULL)
    {
        wCryptoZero(out, outlen);
        return kWCryptoUnavailable;
    }

    status = backend(out, in, inlen);
    if (status != kWCryptoOk)
    {
        wCryptoZero(out, outlen);
    }
    return status;
}

#define DEFINE_HASH_ADAPTER(name, type, function)                                                                      \
    static wcrypto_status_t name(void *out, const unsigned char *in, size_t inlen)                                     \
    {                                                                                                                  \
        return function((type *) out, in, inlen);                                                                      \
    }

#if defined(WCRYPTO_HAS_OPENSSL_HASH)
DEFINE_HASH_ADAPTER(openSSLMD5, md5_hash_t, wCryptoOpenSSLMD5)
DEFINE_HASH_ADAPTER(openSSLSHA1, sha1_hash_t, wCryptoOpenSSLSHA1)
DEFINE_HASH_ADAPTER(openSSLSHA224, sha224_hash_t, wCryptoOpenSSLSHA224)
DEFINE_HASH_ADAPTER(openSSLSHA256, sha256_hash_t, wCryptoOpenSSLSHA256)
DEFINE_HASH_ADAPTER(openSSLSHA384, sha384_hash_t, wCryptoOpenSSLSHA384)
DEFINE_HASH_ADAPTER(openSSLSHA512, sha512_hash_t, wCryptoOpenSSLSHA512)
DEFINE_HASH_ADAPTER(openSSLSHA3_224, sha3_224_hash_t, wCryptoOpenSSLSHA3_224)
DEFINE_HASH_ADAPTER(openSSLSHA3_256, sha3_256_hash_t, wCryptoOpenSSLSHA3_256)
DEFINE_HASH_ADAPTER(openSSLSHA3_384, sha3_384_hash_t, wCryptoOpenSSLSHA3_384)
DEFINE_HASH_ADAPTER(openSSLSHA3_512, sha3_512_hash_t, wCryptoOpenSSLSHA3_512)
#endif
#if defined(WCRYPTO_HAS_SODIUM_HASH)
DEFINE_HASH_ADAPTER(sodiumSHA256, sha256_hash_t, wCryptoSodiumSHA256)
DEFINE_HASH_ADAPTER(sodiumSHA512, sha512_hash_t, wCryptoSodiumSHA512)
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_HASH)
DEFINE_HASH_ADAPTER(softwareMD5, md5_hash_t, wCryptoSoftwareMD5)
DEFINE_HASH_ADAPTER(softwareSHA1, sha1_hash_t, wCryptoSoftwareSHA1)
DEFINE_HASH_ADAPTER(softwareSHA224, sha224_hash_t, wCryptoSoftwareSHA224)
DEFINE_HASH_ADAPTER(softwareSHA256, sha256_hash_t, wCryptoSoftwareSHA256)
DEFINE_HASH_ADAPTER(softwareSHA384, sha384_hash_t, wCryptoSoftwareSHA384)
DEFINE_HASH_ADAPTER(softwareSHA512, sha512_hash_t, wCryptoSoftwareSHA512)
#endif

wcrypto_status_t wCryptoMD5(md5_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLMD5);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, softwareMD5);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA1);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, softwareSHA1);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA224);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, softwareSHA224);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA256);
#elif defined(WCRYPTO_HAS_SODIUM_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, sodiumSHA256);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, softwareSHA256);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA384);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, softwareSHA384);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA512);
#elif defined(WCRYPTO_HAS_SODIUM_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, sodiumSHA512);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, softwareSHA512);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA3_224);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA3_256);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA3_384);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

wcrypto_status_t wCryptoSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    return dispatchHash(out, sizeof(*out), in, inlen, openSSLSHA3_512);
#else
    return dispatchHash(out, sizeof(*out), in, inlen, NULL);
#endif
}

#undef DEFINE_HASH_ADAPTER
