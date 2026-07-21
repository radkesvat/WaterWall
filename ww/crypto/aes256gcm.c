#include "private/crypto_backends.h"
#include "private/crypto_validation.h"
#include "wcrypto.h"

typedef enum wcrypto_aes256gcm_implementation_e
{
    kWCryptoAes256GcmImplementationNone = 0,
    kWCryptoAes256GcmImplementationOpenSSL,
    kWCryptoAes256GcmImplementationSodium,
    kWCryptoAes256GcmImplementationSoftware,
} wcrypto_aes256gcm_implementation_t;

static wcrypto_aes256gcm_implementation_t selectAes256GcmImplementation(void)
{
#if defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    if (wCryptoOpenSSLAES256GCMIsAvailable())
    {
        return kWCryptoAes256GcmImplementationOpenSSL;
    }
#endif
#if defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    if (wCryptoSodiumAES256GCMIsAvailable())
    {
        return kWCryptoAes256GcmImplementationSodium;
    }
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    if (wCryptoSoftwareAES256GCMIsAvailable())
    {
        return kWCryptoAes256GcmImplementationSoftware;
    }
#endif
    return kWCryptoAes256GcmImplementationNone;
}

bool wCryptoAes256GcmIsAvailable(void)
{
    if (! wCryptoIsInitialized())
    {
        return false;
    }
    return selectAes256GcmImplementation() != kWCryptoAes256GcmImplementationNone;
}

wcrypto_status_t wCryptoAes256GcmEncrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
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
    if (! wCryptoIsInitialized())
    {
        wCryptoZero(dst, output_len);
        return kWCryptoInvalidState;
    }
    const wcrypto_aes256gcm_implementation_t implementation = selectAes256GcmImplementation();
    if (implementation == kWCryptoAes256GcmImplementationNone)
    {
        wCryptoZero(dst, output_len);
        return kWCryptoUnavailable;
    }
    switch (implementation)
    {
#if defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    case kWCryptoAes256GcmImplementationOpenSSL:
        status = wCryptoOpenSSLAES256GCMEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
        break;
#endif
#if defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    case kWCryptoAes256GcmImplementationSodium:
        status = wCryptoSodiumAES256GCMEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
        break;
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    case kWCryptoAes256GcmImplementationSoftware:
        status = wCryptoSoftwareAES256GCMEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
        break;
#endif
    default:
        status = kWCryptoUnavailable;
        break;
    }
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    return status;
}

wcrypto_status_t wCryptoAes256GcmDecrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
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
    if (! wCryptoIsInitialized())
    {
        wCryptoZero(dst, output_len);
        return kWCryptoInvalidState;
    }
    const wcrypto_aes256gcm_implementation_t implementation = selectAes256GcmImplementation();
    if (implementation == kWCryptoAes256GcmImplementationNone)
    {
        wCryptoZero(dst, output_len);
        return kWCryptoUnavailable;
    }
    switch (implementation)
    {
#if defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    case kWCryptoAes256GcmImplementationOpenSSL:
        status = wCryptoOpenSSLAES256GCMDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
        break;
#endif
#if defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    case kWCryptoAes256GcmImplementationSodium:
        status = wCryptoSodiumAES256GCMDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
        break;
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    case kWCryptoAes256GcmImplementationSoftware:
        status = wCryptoSoftwareAES256GCMDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
        break;
#endif
    default:
        status = kWCryptoUnavailable;
        break;
    }
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    return status;
}
