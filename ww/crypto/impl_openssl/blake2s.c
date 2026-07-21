#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>

bool wCryptoOpenSSLBlake2sIsAvailable(size_t outlen, size_t keylen)
{
    if (outlen == 0 || outlen > WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE || keylen > WCRYPTO_BLAKE2S_MAX_KEY_SIZE)
    {
        return false;
    }

    if (keylen != 0)
    {
        EVP_MAC   *mac       = EVP_MAC_fetch(NULL, "BLAKE2SMAC", NULL);
        const bool available = mac != NULL;
        EVP_MAC_free(mac);
        return available;
    }
    if (outlen != WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE)
    {
        return false;
    }

    EVP_MD    *md        = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
    const bool available = md != NULL;
    EVP_MD_free(md);
    return available;
}

void wCryptoOpenSSLBlake2sDestroy(wcrypto_openssl_blake2s_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }
    EVP_MD_CTX_free(ctx->md_ctx);
    EVP_MD_free(ctx->md);
    EVP_MAC_CTX_free(ctx->mac_ctx);
    EVP_MAC_free(ctx->mac);
    wCryptoZero(ctx, sizeof(*ctx));
}

wcrypto_status_t wCryptoOpenSSLBlake2sInit(wcrypto_openssl_blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key,
                                           size_t keylen)
{
    wcrypto_status_t status = wCryptoValidateBlake2sInit(ctx, outlen, key, keylen);
    if (status != kWCryptoOk)
    {
        return status;
    }
    memoryZero(ctx, sizeof(*ctx));
    ctx->outlen = outlen;

    if (keylen != 0)
    {
        OSSL_PARAM params[2];
        ctx->mac = EVP_MAC_fetch(NULL, "BLAKE2SMAC", NULL);
        if (ctx->mac == NULL)
        {
            status = kWCryptoUnavailable;
            goto cleanup;
        }
        ctx->mac_ctx = EVP_MAC_CTX_new(ctx->mac);
        if (ctx->mac_ctx == NULL)
        {
            status = kWCryptoBackendFailed;
            goto cleanup;
        }
        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &ctx->outlen);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_MAC_init(ctx->mac_ctx, key, keylen, params) != 1)
        {
            status = kWCryptoBackendFailed;
            goto cleanup;
        }
        return kWCryptoOk;
    }

    if (outlen != WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE)
    {
        status = kWCryptoUnavailable;
        goto cleanup;
    }
    ctx->md = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
    if (ctx->md == NULL)
    {
        status = kWCryptoUnavailable;
        goto cleanup;
    }
    ctx->md_ctx = EVP_MD_CTX_new();
    if (ctx->md_ctx == NULL || EVP_DigestInit_ex(ctx->md_ctx, ctx->md, NULL) != 1)
    {
        status = kWCryptoBackendFailed;
        goto cleanup;
    }
    return kWCryptoOk;

cleanup:
    wCryptoOpenSSLBlake2sDestroy(ctx);
    return status;
}

wcrypto_status_t wCryptoOpenSSLBlake2sUpdate(wcrypto_openssl_blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen)
{
    wcrypto_status_t status = wCryptoValidateBlake2sUpdate(ctx, in, inlen);
    if (status != kWCryptoOk)
    {
        return status;
    }
    if (ctx->mac_ctx != NULL)
    {
        return (inlen == 0 || EVP_MAC_update(ctx->mac_ctx, in, inlen) == 1) ? kWCryptoOk : kWCryptoBackendFailed;
    }
    if (ctx->md_ctx != NULL)
    {
        return (inlen == 0 || EVP_DigestUpdate(ctx->md_ctx, in, inlen) == 1) ? kWCryptoOk : kWCryptoBackendFailed;
    }
    return kWCryptoInvalidState;
}

wcrypto_status_t wCryptoOpenSSLBlake2sFinal(wcrypto_openssl_blake2s_ctx_t *ctx, unsigned char *out, size_t outlen)
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
    if (ctx->outlen == 0 || ctx->outlen > WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE)
    {
        wCryptoZero(out, outlen);
        wCryptoOpenSSLBlake2sDestroy(ctx);
        return kWCryptoInvalidState;
    }
    if (ctx->outlen != outlen)
    {
        wCryptoZero(out, outlen);
        wCryptoOpenSSLBlake2sDestroy(ctx);
        return kWCryptoInvalidArgument;
    }

    wcrypto_status_t status = kWCryptoInvalidState;
    if (ctx->mac_ctx != NULL)
    {
        size_t produced = 0;
        status          = EVP_MAC_final(ctx->mac_ctx, out, &produced, outlen) == 1 && produced == outlen ? kWCryptoOk
                                                                                                         : kWCryptoBackendFailed;
    }
    else if (ctx->md_ctx != NULL)
    {
        unsigned int produced = 0;
        status                = EVP_DigestFinal_ex(ctx->md_ctx, out, &produced) == 1 && produced == outlen ? kWCryptoOk
                                                                                                           : kWCryptoBackendFailed;
    }

    if (status != kWCryptoOk)
    {
        wCryptoZero(out, outlen);
    }
    wCryptoOpenSSLBlake2sDestroy(ctx);
    return status;
}
