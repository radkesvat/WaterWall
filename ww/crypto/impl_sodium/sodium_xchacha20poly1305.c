#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

#include <sodium.h>

wcrypto_status_t wCryptoSodiumXChacha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
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
    static const unsigned char empty    = 0;
    unsigned long long         produced = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            dst, &produced, src != NULL ? src : &empty, src_len, ad != NULL ? ad : &empty, ad_len, NULL, nonce, key) !=
            0 ||
        produced != (unsigned long long) expected_len)
    {
        wCryptoZero(dst, expected_len);
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}
wcrypto_status_t wCryptoSodiumXChacha20Poly1305Decrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
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
    unsigned char              dummy    = 0;
    static const unsigned char empty    = 0;
    unsigned long long         produced = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
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
