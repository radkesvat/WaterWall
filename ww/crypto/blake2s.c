#include "private/crypto_backends.h"
#include "private/crypto_blake2s_internal.h"
#include "private/crypto_validation.h"
#include "wcrypto.h"

static bool blake2sIsActive(const wcrypto_blake2s_internal_t *ctx)
{
    return ctx->magic == WCRYPTO_BLAKE2S_ACTIVE_MAGIC && ctx->implementation != kWCryptoBlake2sImplementationNone;
}

void wCryptoBlake2sDestroy(wcrypto_blake2s_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    wcrypto_blake2s_internal_t *internal = wCryptoBlake2sInternal(ctx);
    if (blake2sIsActive(internal))
    {
        switch (internal->implementation)
        {
#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
        case kWCryptoBlake2sImplementationOpenSSL:
            wCryptoOpenSSLBlake2sDestroy(&internal->backend.openssl);
            break;
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
        case kWCryptoBlake2sImplementationSoftware:
            wCryptoSoftwareBlake2sDestroy(&internal->backend.software);
            break;
#endif
        default:
            break;
        }
    }
    wCryptoZero(ctx, sizeof(*ctx));
}

wcrypto_status_t wCryptoBlake2sInit(wcrypto_blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key, size_t keylen)
{
    wcrypto_status_t status = wCryptoValidateBlake2sInit(ctx, outlen, key, keylen);
    if (status != kWCryptoOk)
    {
        return status;
    }

    wcrypto_blake2s_internal_t *internal = wCryptoBlake2sInternal(ctx);
    if (blake2sIsActive(internal))
    {
        return kWCryptoInvalidState;
    }
    memoryZero(ctx, sizeof(*ctx));
    if (! wCryptoIsInitialized())
    {
        return kWCryptoInvalidState;
    }

    internal->magic  = WCRYPTO_BLAKE2S_ACTIVE_MAGIC;
    internal->outlen = outlen;

#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    if (wCryptoOpenSSLBlake2sIsAvailable(outlen, keylen))
    {
        internal->implementation = kWCryptoBlake2sImplementationOpenSSL;
        status                   = wCryptoOpenSSLBlake2sInit(&internal->backend.openssl, outlen, key, keylen);
    }
    else
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
    {
        internal->implementation = kWCryptoBlake2sImplementationSoftware;
        status                   = wCryptoSoftwareBlake2sInit(&internal->backend.software, outlen, key, keylen);
    }
#else
    {
        status = kWCryptoUnavailable;
    }
#endif

    if (status != kWCryptoOk)
    {
        wCryptoBlake2sDestroy(ctx);
    }
    return status;
}

wcrypto_status_t wCryptoBlake2sUpdate(wcrypto_blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen)
{
    wcrypto_status_t status = wCryptoValidateBlake2sUpdate(ctx, in, inlen);
    if (status != kWCryptoOk)
    {
        return status;
    }

    wcrypto_blake2s_internal_t *internal = wCryptoBlake2sInternal(ctx);
    if (! wCryptoIsInitialized() || ! blake2sIsActive(internal))
    {
        return kWCryptoInvalidState;
    }

    switch (internal->implementation)
    {
#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    case kWCryptoBlake2sImplementationOpenSSL:
        status = wCryptoOpenSSLBlake2sUpdate(&internal->backend.openssl, in, inlen);
        break;
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
    case kWCryptoBlake2sImplementationSoftware:
        status = wCryptoSoftwareBlake2sUpdate(&internal->backend.software, in, inlen);
        break;
#endif
    default:
        status = kWCryptoInvalidState;
        break;
    }

    if (status != kWCryptoOk)
    {
        wCryptoBlake2sDestroy(ctx);
    }
    return status;
}

wcrypto_status_t wCryptoBlake2sFinal(wcrypto_blake2s_ctx_t *ctx, unsigned char *out, size_t outlen)
{
    if (out == NULL || outlen == 0 || outlen > WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE)
    {
        return kWCryptoInvalidArgument;
    }
    if (ctx == NULL)
    {
        wCryptoZero(out, outlen);
        return kWCryptoInvalidArgument;
    }

    wcrypto_blake2s_internal_t *internal = wCryptoBlake2sInternal(ctx);
    if (! wCryptoIsInitialized() || ! blake2sIsActive(internal))
    {
        wCryptoZero(out, outlen);
        wCryptoBlake2sDestroy(ctx);
        return kWCryptoInvalidState;
    }
    if (internal->outlen != outlen)
    {
        wCryptoZero(out, outlen);
        wCryptoBlake2sDestroy(ctx);
        return kWCryptoInvalidArgument;
    }

    wcrypto_status_t status;
    switch (internal->implementation)
    {
#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    case kWCryptoBlake2sImplementationOpenSSL:
        status = wCryptoOpenSSLBlake2sFinal(&internal->backend.openssl, out, outlen);
        break;
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
    case kWCryptoBlake2sImplementationSoftware:
        status = wCryptoSoftwareBlake2sFinal(&internal->backend.software, out, outlen);
        break;
#endif
    default:
        status = kWCryptoInvalidState;
        break;
    }

    if (status != kWCryptoOk)
    {
        wCryptoZero(out, outlen);
    }
    wCryptoBlake2sDestroy(ctx);
    return status;
}

wcrypto_status_t wCryptoBlake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen,
                                const unsigned char *in, size_t inlen)
{
    if (out == NULL)
    {
        return kWCryptoInvalidArgument;
    }
    if (in == NULL && inlen != 0)
    {
        if (outlen > 0 && outlen <= WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE)
        {
            wCryptoZero(out, outlen);
        }
        return kWCryptoInvalidArgument;
    }

    wcrypto_blake2s_ctx_t ctx    = WCRYPTO_BLAKE2S_CONTEXT_INITIALIZER;
    wcrypto_status_t      status = wCryptoBlake2sInit(&ctx, outlen, key, keylen);
    if (status == kWCryptoOk)
    {
        status = wCryptoBlake2sUpdate(&ctx, in, inlen);
    }
    if (status == kWCryptoOk)
    {
        status = wCryptoBlake2sFinal(&ctx, out, outlen);
    }
    else
    {
        if (outlen > 0 && outlen <= WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE)
        {
            wCryptoZero(out, outlen);
        }
        wCryptoBlake2sDestroy(&ctx);
    }
    return status;
}
