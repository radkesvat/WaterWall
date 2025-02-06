#include "crypto/helpers.h"
#include "wlibc.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

// Helper function for encryption using EVP API
int chacha20poly1305_encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx            = NULL;
    int             len            = 0;
    int             ciphertext_len = 0;
    int             ret            = 0;

    // Initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (! ctx)
    {
        goto cleanup;
    }

    // Initialize encryption operation with ChaCha20-Poly1305
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        goto cleanup;
    }

    // Set additional authenticated data (AAD)
    if (EVP_EncryptUpdate(ctx, NULL, &len, ad, adlen) != 1)
    {
        goto cleanup;
    }

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, dst, &len, src, srclen) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, dst + ciphertext_len, &len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += len;

    // Get the tag (16 bytes for Poly1305)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, dst + ciphertext_len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += 16;

    ret = 1; // Success

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret ? ciphertext_len : -1;
}

// Helper function for decryption using EVP API
int chacha20poly1305_decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx           = NULL;
    int             len           = 0;
    int             plaintext_len = 0;
    int             ret           = 0;

    // Initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (! ctx)
    {
        goto cleanup;
    }

    // Initialize decryption operation with ChaCha20-Poly1305
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        goto cleanup;
    }

    // Set additional authenticated data (AAD)
    if (EVP_DecryptUpdate(ctx, NULL, &len, ad, adlen) != 1)
    {
        goto cleanup;
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, dst, &len, src, srclen - 16) != 1)
    {
        goto cleanup;
    }
    plaintext_len += len;

    // Set the tag (last 16 bytes of the input)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *) (src + srclen - 16)) != 1)
    {
        goto cleanup;
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, dst + plaintext_len, &len) != 1)
    {
        goto cleanup;
    }
    plaintext_len += len;

    ret = 1; // Success

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret ? plaintext_len : -1;
}

// Similar functions for XChaCha20-Poly1305
int xchacha20poly1305_encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                              size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    // OpenSSL does not directly support XChaCha20-Poly1305 via EVP.
    // You would need to use libsodium or another library for this.
    return -1; // Not implemented
}

int xchacha20poly1305_decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                              size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    // OpenSSL does not directly support XChaCha20-Poly1305 via EVP.
    // You would need to use libsodium or another library for this.
    return -1; // Not implemented
}

// Define the macros
#define wireguard_aead_encrypt(dst, src, srclen, ad, adlen, nonce, key)                                                \
    chacha20poly1305_encrypt(dst, src, srclen, ad, adlen, nonce, key)

#define wireguard_aead_decrypt(dst, src, srclen, ad, adlen, nonce, key)                                                \
    chacha20poly1305_decrypt(dst, src, srclen, ad, adlen, nonce, key)

#define wireguard_xaead_encrypt(dst, src, srclen, ad, adlen, nonce, key)                                               \
    xchacha20poly1305_encrypt(dst, src, srclen, ad, adlen, nonce, key)

#define wireguard_xaead_decrypt(dst, src, srclen, ad, adlen, nonce, key)                                               \
    xchacha20poly1305_decrypt(dst, src, srclen, ad, adlen, nonce, key)