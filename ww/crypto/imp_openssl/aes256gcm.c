#include "wcrypto.h"
#include "wlibc.h"

#include <openssl/evp.h>

int aes256gcmIsAvailable(void)
{
    return EVP_aes_256_gcm() != NULL;
}

int aes256gcmEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                     size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int             len = 0;
    int             ret = -1;
    int             ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (! ctx)
    {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
    {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    {
        goto cleanup;
    }

    if (ad != NULL && ad_len > 0)
    {
        if (EVP_EncryptUpdate(ctx, NULL, &len, ad, (int) ad_len) != 1)
        {
            goto cleanup;
        }
    }

    if (EVP_EncryptUpdate(ctx, dst, &len, src, (int) src_len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += len;

    len = 0;
    if (EVP_EncryptFinal_ex(ctx, dst + ciphertext_len, &len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, dst + ciphertext_len) != 1)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes256gcmDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                     size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int             len = 0;
    int             ret = -1;
    int             plaintext_len = 0;

    if (src_len < 16)
    {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (! ctx)
    {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
    {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    {
        goto cleanup;
    }

    if (ad != NULL && ad_len > 0)
    {
        if (EVP_DecryptUpdate(ctx, NULL, &len, ad, (int) ad_len) != 1)
        {
            goto cleanup;
        }
    }

    if (EVP_DecryptUpdate(ctx, dst, &len, src, (int) (src_len - 16)) != 1)
    {
        goto cleanup;
    }
    plaintext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *) (src + src_len - 16)) != 1)
    {
        goto cleanup;
    }

    len = 0;
    if (EVP_DecryptFinal_ex(ctx, dst + plaintext_len, &len) != 1)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
