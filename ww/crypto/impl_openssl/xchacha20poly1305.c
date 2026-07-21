#include "../impl_software/private/defs.h"
#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

wcrypto_status_t wCryptoOpenSSLXChacha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity,
                                                        const unsigned char *src, size_t src_len,
                                                        const unsigned char *ad, size_t ad_len,
                                                        const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
                                                        const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           output_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &output_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
        return status;
    }
    uint8_t subkey[CHACHA20_KEY_SIZE]               = {0};
    uint8_t derived_nonce[CHACHA20_IETF_NONCE_SIZE] = {0};
    memoryCopy(derived_nonce + 4, nonce + 16, 8);
    hchacha20(subkey, nonce, key);
    status = wCryptoOpenSSLChacha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, derived_nonce, subkey);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    wCryptoZero(subkey, sizeof(subkey));
    wCryptoZero(derived_nonce, sizeof(derived_nonce));
    return status;
}

wcrypto_status_t wCryptoOpenSSLXChacha20Poly1305Decrypt(unsigned char *dst, size_t dst_capacity,
                                                        const unsigned char *src, size_t src_len,
                                                        const unsigned char *ad, size_t ad_len,
                                                        const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
                                                        const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    size_t           output_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &output_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
        return status;
    }
    uint8_t subkey[CHACHA20_KEY_SIZE]               = {0};
    uint8_t derived_nonce[CHACHA20_IETF_NONCE_SIZE] = {0};
    memoryCopy(derived_nonce + 4, nonce + 16, 8);
    hchacha20(subkey, nonce, key);
    status = wCryptoOpenSSLChacha20Poly1305Decrypt(dst, dst_capacity, src, src_len, ad, ad_len, derived_nonce, subkey);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    wCryptoZero(subkey, sizeof(subkey));
    wCryptoZero(derived_nonce, sizeof(derived_nonce));
    return status;
}
