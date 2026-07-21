#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <openssl/evp.h>

wcrypto_status_t wCryptoOpenSSLChacha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                       const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           expected_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &expected_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, expected_len);
        return status;
    }

    static const unsigned char empty          = 0;
    EVP_CIPHER_CTX            *ctx            = EVP_CIPHER_CTX_new();
    int                        len            = 0;
    int                        ciphertext_len = 0;
    status                                    = kWCryptoBackendFailed;
    if (ctx == NULL || EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        goto cleanup;
    }
    if (ad_len != 0 && EVP_EncryptUpdate(ctx, NULL, &len, ad, (int) ad_len) != 1)
    {
        goto cleanup;
    }
    if (EVP_EncryptUpdate(ctx, dst, &len, src != NULL ? src : &empty, (int) src_len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, dst + ciphertext_len, &len) != 1)
    {
        goto cleanup;
    }
    ciphertext_len += len;
    if ((size_t) ciphertext_len != src_len ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, WCRYPTO_AEAD_TAG_SIZE, dst + ciphertext_len) != 1)
    {
        goto cleanup;
    }
    status = kWCryptoOk;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, expected_len);
    }
    return status;
}

wcrypto_status_t wCryptoOpenSSLChacha20Poly1305Decrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                       const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           expected_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &expected_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, expected_len);
        return status;
    }

    unsigned char   dummy         = 0;
    unsigned char  *actual_dst    = dst != NULL ? dst : &dummy;
    EVP_CIPHER_CTX *ctx           = EVP_CIPHER_CTX_new();
    int             len           = 0;
    int             plaintext_len = 0;
    status                        = kWCryptoBackendFailed;
    if (ctx == NULL || EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1)
    {
        goto cleanup;
    }
    if (ad_len != 0 && EVP_DecryptUpdate(ctx, NULL, &len, ad, (int) ad_len) != 1)
    {
        goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, actual_dst, &len, src, (int) expected_len) != 1)
    {
        goto cleanup;
    }
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, WCRYPTO_AEAD_TAG_SIZE, (void *) (src + expected_len)) != 1)
    {
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(ctx, actual_dst + plaintext_len, &len) != 1)
    {
        status = kWCryptoAuthenticationFailed;
        goto cleanup;
    }
    plaintext_len += len;
    status = (size_t) plaintext_len == expected_len ? kWCryptoOk : kWCryptoBackendFailed;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, expected_len);
    }
    return status;
}
