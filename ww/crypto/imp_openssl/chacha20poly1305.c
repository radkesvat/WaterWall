#include "wcrypto.h"
#include "wlibc.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

// Helper function for encryption using EVP API
int chacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ret = -1; // default to error
    int ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, ad, adlen) != 1)
    {
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, dst, &len, src, srclen) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, dst + ciphertext_len, &len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, dst + ciphertext_len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += 16;

    ret = 0; // success

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// Helper function for decryption using EVP API
int chacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ret = -1; // default to error
    int plaintext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, ad, adlen) != 1)
    {
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, dst, &len, src, srclen - 16) != 1)
    {
        goto cleanup;
    }
    plaintext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(src + srclen - 16)) != 1)
    {
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, dst + plaintext_len, &len) != 1)
    {
        goto cleanup;
    }
    plaintext_len += len;

    ret = 0; // success

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
