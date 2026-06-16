#include "private/crypto_backends.h"
#include "wlibc.h"
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static void blake2sCleanup(blake2s_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    EVP_MD_CTX_free(ctx->md_ctx);
    EVP_MD_free(ctx->md);
    EVP_MAC_CTX_free(ctx->mac_ctx);
    EVP_MAC_free(ctx->mac);

    ctx->md_ctx  = NULL;
    ctx->md      = NULL;
    ctx->mac_ctx = NULL;
    ctx->mac     = NULL;
    ctx->outlen  = 0;
}

int wCryptoOpenSSLBlake2sInit(blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key, size_t keylen)
{
    if (!ctx || outlen == 0 || outlen > 32 || keylen > 32)
    {
        printError("Invalid parameters for BLAKE2s initialization.\n");
        return -1;
    }

    blake2sCleanup(ctx);
    ctx->outlen = outlen;

    if (key && keylen > 0)
    {
        OSSL_PARAM params[2];

        ctx->mac = EVP_MAC_fetch(NULL, "BLAKE2SMAC", NULL);
        if (!ctx->mac)
        {
            printError("Failed to fetch OpenSSL BLAKE2SMAC implementation.\n");
            blake2sCleanup(ctx);
            return -1;
        }

        ctx->mac_ctx = EVP_MAC_CTX_new(ctx->mac);
        if (!ctx->mac_ctx)
        {
            printError("Failed to allocate OpenSSL BLAKE2SMAC context.\n");
            blake2sCleanup(ctx);
            return -1;
        }

        params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &ctx->outlen);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_MAC_init(ctx->mac_ctx, key, keylen, params) != 1)
        {
            printError("Failed to initialize OpenSSL BLAKE2SMAC context.\n");
            blake2sCleanup(ctx);
            return -1;
        }

        return 0;
    }

    if (outlen != 32)
    {
        printError("OpenSSL BLAKE2s without a key only supports 32-byte output in this backend.\n");
        blake2sCleanup(ctx);
        return -1;
    }

    ctx->md = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
    if (!ctx->md)
    {
        printError("Failed to fetch OpenSSL BLAKE2S-256 implementation.\n");
        blake2sCleanup(ctx);
        return -1;
    }

    ctx->md_ctx = EVP_MD_CTX_new();
    if (!ctx->md_ctx)
    {
        printError("Failed to allocate OpenSSL BLAKE2S-256 context.\n");
        blake2sCleanup(ctx);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx->md_ctx, ctx->md, NULL) != 1)
    {
        printError("Failed to initialize OpenSSL BLAKE2S-256 context.\n");
        blake2sCleanup(ctx);
        return -1;
    }

    return 0;
}

int wCryptoOpenSSLBlake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen)
{
    if (!ctx)
    {
        printError("Invalid BLAKE2s context.\n");
        return -1;
    }

    if (inlen == 0)
    {
        return 0;
    }

    if (!in)
    {
        printError("Invalid input for BLAKE2s update.\n");
        return -1;
    }

    if (ctx->mac_ctx)
    {
        if (EVP_MAC_update(ctx->mac_ctx, in, inlen) != 1)
        {
            printError("Failed to update OpenSSL BLAKE2SMAC context.\n");
            return -1;
        }

        return 0;
    }

    if (ctx->md_ctx)
    {
        if (EVP_DigestUpdate(ctx->md_ctx, in, inlen) != 1)
        {
            printError("Failed to update OpenSSL BLAKE2S-256 context.\n");
            return -1;
        }

        return 0;
    }

    printError("BLAKE2s update called on an uninitialized OpenSSL context.\n");
    return -1;
}

int wCryptoOpenSSLBlake2sFinal(blake2s_ctx_t *ctx, unsigned char *out)
{
    int result = -1;

    if (!ctx || !out)
    {
        printError("Invalid input for BLAKE2s finalization.\n");
        return -1;
    }

    if (ctx->mac_ctx)
    {
        size_t hash_len = 0;

        if (EVP_MAC_final(ctx->mac_ctx, out, &hash_len, ctx->outlen) != 1)
        {
            printError("Failed to finalize OpenSSL BLAKE2SMAC context.\n");
            goto cleanup;
        }

        result = 0;
        goto cleanup;
    }

    if (ctx->md_ctx)
    {
        unsigned int hash_len = 0;

        if (EVP_DigestFinal_ex(ctx->md_ctx, out, &hash_len) != 1)
        {
            printError("Failed to finalize OpenSSL BLAKE2S-256 context.\n");
            goto cleanup;
        }

        result = (hash_len == ctx->outlen) ? 0 : -1;
        if (result != 0)
        {
            printError("Unexpected OpenSSL BLAKE2S-256 output length.\n");
        }

        goto cleanup;
    }

    printError("BLAKE2s final called on an uninitialized OpenSSL context.\n");

cleanup:
    blake2sCleanup(ctx);
    return result;
}

int wCryptoOpenSSLBlake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen, const unsigned char *in,
            size_t inlen)
{
    blake2s_ctx_t ctx = {0};

    if (wCryptoOpenSSLBlake2sInit(&ctx, outlen, key, keylen) != 0)
    {
        return -1;
    }

    if (wCryptoOpenSSLBlake2sUpdate(&ctx, in, inlen) != 0)
    {
        blake2sCleanup(&ctx);
        return -1;
    }

    if (wCryptoOpenSSLBlake2sFinal(&ctx, out) != 0)
    {
        return -1;
    }

    return 0;
}
