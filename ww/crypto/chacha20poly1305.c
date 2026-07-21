#include "private/crypto_backends.h"
#include "private/crypto_validation.h"
#include "wcrypto.h"

wcrypto_status_t wCryptoChaCha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                                size_t src_len, const unsigned char *ad, size_t ad_len,
                                                const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
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
    if (! wCryptoIsInitialized())
    {
        wCryptoZero(dst, output_len);
        return kWCryptoInvalidState;
    }
#if defined(WCRYPTO_HAS_OPENSSL_CHACHA20POLY1305)
    status = wCryptoOpenSSLChacha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SODIUM_CHACHA20POLY1305)
    status = wCryptoSodiumChacha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SOFTWARE_CHACHA20POLY1305)
    status = wCryptoSoftwareChacha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
#else
    status = kWCryptoUnavailable;
#endif
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    return status;
}

wcrypto_status_t wCryptoChaCha20Poly1305Decrypt(unsigned char *dst, size_t dst_capacity, const unsigned char *src,
                                                size_t src_len, const unsigned char *ad, size_t ad_len,
                                                const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
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
    if (! wCryptoIsInitialized())
    {
        wCryptoZero(dst, output_len);
        return kWCryptoInvalidState;
    }
#if defined(WCRYPTO_HAS_OPENSSL_CHACHA20POLY1305)
    status = wCryptoOpenSSLChacha20Poly1305Decrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SODIUM_CHACHA20POLY1305)
    status = wCryptoSodiumChacha20Poly1305Decrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SOFTWARE_CHACHA20POLY1305)
    status = wCryptoSoftwareChacha20Poly1305Decrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
#else
    status = kWCryptoUnavailable;
#endif
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, output_len);
    }
    return status;
}
