#include "wcrypto.h"
#include "wlibc.h"

#include "private/crypto_backends.h"

int blake2sInit(blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key, size_t keylen)
{
#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    return wCryptoOpenSSLBlake2sInit(ctx, outlen, key, keylen);
#elif defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
    return wCryptoSoftwareBlake2sInit(ctx, outlen, key, keylen);
#else
    discard ctx;
    discard outlen;
    discard key;
    discard keylen;
    return -1;
#endif
}

int blake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    return wCryptoOpenSSLBlake2sUpdate(ctx, in, inlen);
#elif defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
    return wCryptoSoftwareBlake2sUpdate(ctx, in, inlen);
#else
    discard ctx;
    discard in;
    discard inlen;
    return -1;
#endif
}

int blake2sFinal(blake2s_ctx_t *ctx, unsigned char *out)
{
#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    return wCryptoOpenSSLBlake2sFinal(ctx, out);
#elif defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
    return wCryptoSoftwareBlake2sFinal(ctx, out);
#else
    discard ctx;
    discard out;
    return -1;
#endif
}

int blake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen, const unsigned char *in,
            size_t inlen)
{
#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    return wCryptoOpenSSLBlake2s(out, outlen, key, keylen, in, inlen);
#elif defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
    return wCryptoSoftwareBlake2s(out, outlen, key, keylen, in, inlen);
#else
    discard out;
    discard outlen;
    discard key;
    discard keylen;
    discard in;
    discard inlen;
    return -1;
#endif
}
