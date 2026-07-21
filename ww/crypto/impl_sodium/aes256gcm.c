#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <sodium.h>

bool wCryptoSodiumAES256GCMIsAvailable(void)
{
    return crypto_aead_aes256gcm_is_available() != 0;
}

wcrypto_status_t wCryptoSodiumAES256GCMEncrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                               size_t src_len, const unsigned char *ad, size_t ad_len,
                                               const unsigned char nonce[WCRYPTO_AES256GCM_NONCE_SIZE],
                                               const unsigned char key[WCRYPTO_AES256GCM_KEY_SIZE])
{
    size_t           expected_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &expected_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, expected_len);
        return status;
    }
    if (! wCryptoSodiumAES256GCMIsAvailable())
    {
        wCryptoZero(dst, expected_len);
        return kWCryptoUnavailable;
    }

    static const unsigned char empty    = 0;
    unsigned long long         produced = 0;
    if (crypto_aead_aes256gcm_encrypt(
            dst, &produced, src != NULL ? src : &empty, src_len, ad != NULL ? ad : &empty, ad_len, NULL, nonce, key) !=
            0 ||
        produced != (unsigned long long) expected_len)
    {
        wCryptoZero(dst, expected_len);
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}

wcrypto_status_t wCryptoSodiumAES256GCMDecrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                               size_t src_len, const unsigned char *ad, size_t ad_len,
                                               const unsigned char nonce[WCRYPTO_AES256GCM_NONCE_SIZE],
                                               const unsigned char key[WCRYPTO_AES256GCM_KEY_SIZE])
{
    size_t           expected_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &expected_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, expected_len);
        return status;
    }
    if (! wCryptoSodiumAES256GCMIsAvailable())
    {
        wCryptoZero(dst, expected_len);
        return kWCryptoUnavailable;
    }

    unsigned char              dummy    = 0;
    static const unsigned char empty    = 0;
    unsigned long long         produced = 0;
    if (crypto_aead_aes256gcm_decrypt(
            dst != NULL ? dst : &dummy, &produced, NULL, src, src_len, ad != NULL ? ad : &empty, ad_len, nonce, key) !=
        0)
    {
        wCryptoZero(dst, expected_len);
        return kWCryptoAuthenticationFailed;
    }
    if (produced != (unsigned long long) expected_len)
    {
        wCryptoZero(dst, expected_len);
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}
