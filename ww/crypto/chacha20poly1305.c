#include "crypto/helpers.h"
#include "wlibc.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "sodium.h"

// Helper function for encryption using EVP API
int chacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
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
int chacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
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

// Encrypt function
int xchacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen,
                              const unsigned char *ad, size_t adlen,
                              const unsigned char *nonce, const unsigned char *key) {
    // Destination buffer must have space for ciphertext + authentication tag
    unsigned long long ciphertext_len = srclen + crypto_aead_xchacha20poly1305_ietf_ABYTES;

    // Perform encryption
    int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
        dst, &ciphertext_len, src, srclen, ad, adlen, NULL, nonce, key);

    if (result != 0) {
        printError("Encryption failed\n");
        return -1;
    }

    return 0; // Success
}

// Decrypt function
int xchacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen,
                              const unsigned char *ad, size_t adlen,
                              const unsigned char *nonce, const unsigned char *key) {

    // Destination buffer must have space for plaintext
    unsigned long long plaintext_len = srclen - crypto_aead_xchacha20poly1305_ietf_ABYTES;

    // Perform decryption
    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
        dst, &plaintext_len, NULL, src, srclen, ad, adlen, nonce, key);

    if (result != 0) {
        printError("Decryption failed (possible tampering or invalid inputs)\n");
        return -1;
    }

    return 0; // Success
}
