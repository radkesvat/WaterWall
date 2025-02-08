#include "wcrypto.h"
#include "wlibc.h"

#include "sodium.h"

typedef crypto_generichash_state blake2s_ctx_t;

// Function to initialize the BLAKE2s context
int blake2sInit(blake2s_ctx_t **ctx, size_t outlen, const unsigned char *key, size_t keylen)
{
    // Ensure libsodium is initialized
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");

    // Validate output length
    if (outlen == 0 || outlen > crypto_generichash_BYTES_MAX || outlen < crypto_generichash_BYTES_MIN)
    {
        printError("Invalid output length for BLAKE2s\n");
        return -1;
    }

    // Validate key length
    if (keylen > crypto_generichash_KEYBYTES_MAX)
    {
        printError("Invalid key length for BLAKE2s\n");
        return -1;
    }

    // Allocate memory for the context
    *ctx = (blake2s_ctx_t *) malloc(sizeof(blake2s_ctx_t));
    if (*ctx == NULL)
    {
        printError("Failed to allocate memory for BLAKE2s context\n");
        return -1;
    }

    // Initialize the BLAKE2s context
    if (crypto_generichash_init(*ctx, key, keylen, outlen) != 0)
    {
        printError("Failed to initialize BLAKE2s context\n");
        free(*ctx);
        return -1;
    }

    return 0; // Success
}

// Function to update the BLAKE2s context with input data
int blake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen)
{
    if (ctx == NULL || in == NULL)
    {
        printError("Invalid input to BLAKE2s update\n");
        return -1;
    }

    // Update the context with new input data
    if (crypto_generichash_update(ctx, in, inlen) != 0)
    {
        printError("Failed to update BLAKE2s context\n");
        return -1;
    }

    return 0; // Success
}

// Function to finalize the BLAKE2s hash computation
int blake2sFinal(blake2s_ctx_t *ctx, unsigned char *out)
{
    if (ctx == NULL || out == NULL)
    {
        printError("Invalid input to BLAKE2s finalization\n");
        return -1;
    }

    // Finalize the hash computation
    if (crypto_generichash_final(ctx, out, crypto_generichash_BYTES) != 0)
    {
        printError("Failed to finalize BLAKE2s hash\n");
        return -1;
    }

    // Free the context
    free(ctx);

    return 0; // Success
}

// One-shot function to compute BLAKE2s hash
int blake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen, const unsigned char *in,
            size_t inlen)
{
    // Ensure libsodium is initialized
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");

    // Validate output length
    if (outlen == 0 || outlen > crypto_generichash_BYTES_MAX || outlen < crypto_generichash_BYTES_MIN)
    {
        printError("Invalid output length for BLAKE2s\n");
        return -1;
    }

    // Validate key length
    if (keylen > crypto_generichash_KEYBYTES_MAX)
    {
        printError("Invalid key length for BLAKE2s\n");
        return -1;
    }

    // Compute the hash in one shot
    if (crypto_generichash(out, outlen, in, inlen, key, keylen) != 0)
    {
        printError("Failed to compute BLAKE2s hash\n");
        return -1;
    }

    return 0; // Success
}