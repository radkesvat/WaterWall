#include "wcrypto.h"
#include "wlibc.h"

#include "private/crypto_backends.h"

int aes256gcmIsAvailable(void)
{
#if defined(WCRYPTO_BACKEND_SODIUM) && defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    return wCryptoSodiumAES256GCMIsAvailable();
#elif defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    return wCryptoOpenSSLAES256GCMIsAvailable();
#elif defined(WCRYPTO_BACKEND_SOFTWARE) && defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    return wCryptoSoftwareAES256GCMIsAvailable();
#elif defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    return wCryptoSodiumAES256GCMIsAvailable();
#elif defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    return wCryptoOpenSSLAES256GCMIsAvailable();
#elif defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    return wCryptoSoftwareAES256GCMIsAvailable();
#else
    return 0;
#endif
}

int aes256gcmEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                     size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
#if defined(WCRYPTO_BACKEND_SODIUM) && defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    return wCryptoSodiumAES256GCMEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    return wCryptoOpenSSLAES256GCMEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_BACKEND_SOFTWARE) && defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    return wCryptoSoftwareAES256GCMEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    return wCryptoSodiumAES256GCMEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    return wCryptoOpenSSLAES256GCMEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    return wCryptoSoftwareAES256GCMEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
#else
    discard dst;
    discard src;
    discard src_len;
    discard ad;
    discard ad_len;
    discard nonce;
    discard key;
    return -1;
#endif
}

int aes256gcmDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                     size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
#if defined(WCRYPTO_BACKEND_SODIUM) && defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    return wCryptoSodiumAES256GCMDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_BACKEND_OPENSSL) && defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    return wCryptoOpenSSLAES256GCMDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_BACKEND_SOFTWARE) && defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    return wCryptoSoftwareAES256GCMDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    return wCryptoSodiumAES256GCMDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    return wCryptoOpenSSLAES256GCMDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    return wCryptoSoftwareAES256GCMDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
#else
    discard dst;
    discard src;
    discard src_len;
    discard ad;
    discard ad_len;
    discard nonce;
    discard key;
    return -1;
#endif
}
