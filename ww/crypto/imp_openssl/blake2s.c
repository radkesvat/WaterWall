#include "wcrypto.h"
#include "wlibc.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

// Define the context type
typedef EVP_MAC_CTX blake2s_ctx_t;

int blake2sInit(blake2s_ctx_t **ctx, size_t outlen, const unsigned char *key, size_t keylen)
{
    if (!ctx || outlen == 0 || outlen > 32) 
    {
        printError("Invalid parameters: ctx is NULL or output length is out of range.\n");
        return -1;
    }

    // Create a new MAC context for BLAKE2s
    *ctx = EVP_MAC_CTX_new(EVP_MAC_fetch(NULL, "BLAKE2s", NULL));
    if (!*ctx) 
    {
        printError("Failed to allocate EVP_MAC_CTX.\n");
        return -1;
    }

    // Set the output length using OSSL_PARAM
    OSSL_PARAM params[3];
    size_t params_idx = 0;

    params[params_idx++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &outlen);

    if (key && keylen > 0) 
    {
        params[params_idx++] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)key, keylen);
    }

    params[params_idx] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(*ctx, NULL, 0, params) != 1) 
    {
        printError("Failed to initialize BLAKE2s context.\n");
        EVP_MAC_CTX_free(*ctx);
        *ctx = NULL;
        return -1;
    }

    return 0; // Success
}

// Function to update the BLAKE2s context with input data
int blake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen)
{
    if (!ctx || !in)
    {
        printError("Invalid input for BLAKE2s update.\n");
        return -1;
    }

    if (EVP_MAC_update(ctx, in, inlen) != 1)
    {
        printError("Failed to update BLAKE2s context.\n");
        return -1;
    }

    return 0; // Success
}

// Function to finalize the BLAKE2s hash computation
int blake2sFinal(blake2s_ctx_t *ctx, unsigned char *out)
{
    if (!ctx || !out)
    {
        printError("Invalid input for BLAKE2s finalization.\n");
        return -1;
    }

    size_t hash_len;
    if (EVP_MAC_final(ctx, out, &hash_len, EVP_MAX_MD_SIZE) != 1)
    {
        printError("Failed to finalize BLAKE2s hash.\n");
        EVP_MAC_CTX_free(ctx);
        return -1;
    }

    EVP_MAC_CTX_free(ctx); // Free the context after finalization
    return 0;              // Success
}

// One-shot function to compute BLAKE2s hash
int blake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen, const unsigned char *in,
            size_t inlen)
{
    blake2s_ctx_t *ctx = NULL;

    // Initialize the context
    if (blake2sInit(&ctx, outlen, key, keylen) < 0)
    {
        return -1;
    }

    // Update the context with input data
    if (blake2sUpdate(ctx, in, inlen) < 0)
    {
        EVP_MAC_CTX_free(ctx);
        return -1;
    }

    // Finalize the hash computation
    if (blake2sFinal(ctx, out) < 0)
    {
        return -1;
    }

    return 0; // Success
}
