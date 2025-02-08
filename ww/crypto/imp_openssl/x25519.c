#include "wcrypto.h"
#include "wlibc.h"
#include <openssl/ec.h>
#include <openssl/evp.h>

// Function to perform X25519 scalar multiplication
int performX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32])
{
    // Validate inputs
    if (!out || !scalar || !point)
    {
        printError("Invalid input for X25519.\n");
        return -1;
    }

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *privkey = NULL;
    EVP_PKEY *pubkey = NULL;

    // Create the private key from the scalar
    privkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, scalar, 32);
    if (!privkey)
    {
        printError("Failed to create X25519 private key.\n");
        goto err;
    }

    // Create the public key from the point
    pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, point, 32);
    if (!pubkey)
    {
        printError("Failed to create X25519 public key.\n");
        goto err;
    }

    // Create a new context for X25519 using the private key
    ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx)
    {
        printError("Failed to create X25519 context.\n");
        goto err;
    }

    // Initialize the context for key derivation
    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        printError("Failed to initialize X25519 context.\n");
        goto err;
    }

    // Set the peer's public key in the context (OpenSSL 3.0+ uses EVP_PKEY_derive_set_peer)
    if (EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0)
    {
        printError("Failed to set X25519 peer public key.\n");
        goto err;
    }

    // Derive the shared secret
    size_t secret_len = 32;
    if (EVP_PKEY_derive(ctx, out, &secret_len) <= 0)
    {
        printError("Failed to derive X25519 shared secret.\n");
        goto err;
    }

    // Clean up
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_CTX_free(ctx);

    return 0; // Success

err:
    // Error cleanup
    if (privkey) EVP_PKEY_free(privkey);
    if (pubkey) EVP_PKEY_free(pubkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);

    return -1; // Failure
}
