#include "wcrypto.h"
#include "wlibc.h"

#include "private/crypto_backends.h"

static _Noreturn void unsupportedHash(const char *name)
{
    printError("%s is not implemented by the selected crypto backend or any compiled fallback.\n", name);
    terminateProgram(1);
}

int wCryptoMD5(md5_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLMD5(out, in, inlen);
#elif defined(WCRYPTO_BACKEND_SOFTWARE) && defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareMD5(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLMD5(out, in, inlen);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareMD5(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoMD5");
#endif
}

int wCryptoSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA1(out, in, inlen);
#elif defined(WCRYPTO_BACKEND_SOFTWARE) && defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareSHA1(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA1(out, in, inlen);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareSHA1(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA1");
#endif
}

int wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA224(out, in, inlen);
#elif defined(WCRYPTO_BACKEND_SOFTWARE) && defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareSHA224(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA224(out, in, inlen);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareSHA224(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA224");
#endif
}

int wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_SODIUM) && defined(WCRYPTO_HAS_SODIUM_HASH)
    return wCryptoSodiumSHA256(out, in, inlen);
#elif defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA256(out, in, inlen);
#elif defined(WCRYPTO_BACKEND_SOFTWARE) && defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareSHA256(out, in, inlen);
#elif defined(WCRYPTO_HAS_SODIUM_HASH)
    return wCryptoSodiumSHA256(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA256(out, in, inlen);
#elif defined(WCRYPTO_HAS_SOFTWARE_HASH)
    return wCryptoSoftwareSHA256(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA256");
#endif
}

int wCryptoSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA384(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA384(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA384");
#endif
}

int wCryptoSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_SODIUM) && defined(WCRYPTO_HAS_SODIUM_HASH)
    return wCryptoSodiumSHA512(out, in, inlen);
#elif defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA512(out, in, inlen);
#elif defined(WCRYPTO_HAS_SODIUM_HASH)
    return wCryptoSodiumSHA512(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA512(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA512");
#endif
}

int wCryptoSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_224(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_224(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA3_224");
#endif
}

int wCryptoSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_256(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_256(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA3_256");
#endif
}

int wCryptoSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_384(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_384(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA3_384");
#endif
}

int wCryptoSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_512(out, in, inlen);
#elif defined(WCRYPTO_HAS_OPENSSL_HASH)
    return wCryptoOpenSSLSHA3_512(out, in, inlen);
#else
    discard out;
    discard in;
    discard inlen;
    unsupportedHash("wCryptoSHA3_512");
#endif
}
