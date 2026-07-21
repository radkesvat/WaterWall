#include "private/crypto_backends.h"
#include "private/crypto_validation.h"

bool wCryptoSoftwareAES256GCMIsAvailable(void)
{
    return false;
}

wcrypto_status_t wCryptoSoftwareAES256GCMEncrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                                 size_t src_len, const unsigned char *ad, size_t ad_len,
                                                 const unsigned char nonce[WCRYPTO_AES256GCM_NONCE_SIZE],
                                                 const unsigned char key[WCRYPTO_AES256GCM_KEY_SIZE])
{
    size_t           output_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &output_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
        return status;
    }
    wCryptoZero(dst, output_len);
    return kWCryptoUnavailable;
}

wcrypto_status_t wCryptoSoftwareAES256GCMDecrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                                 size_t src_len, const unsigned char *ad, size_t ad_len,
                                                 const unsigned char nonce[WCRYPTO_AES256GCM_NONCE_SIZE],
                                                 const unsigned char key[WCRYPTO_AES256GCM_KEY_SIZE])
{
    size_t           output_len = 0;
    wcrypto_status_t status =
        wCryptoValidateAeadDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key, &output_len);
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
        return status;
    }
    wCryptoZero(dst, output_len);
    return kWCryptoUnavailable;
}
