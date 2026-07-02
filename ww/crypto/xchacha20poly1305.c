#include "wcrypto.h"
#include "wlibc.h"

#include "private/crypto_backends.h"

int xchacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                             size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
#if defined(WCRYPTO_HAS_OPENSSL_XCHACHA20POLY1305)
    return wCryptoOpenSSLXChacha20Poly1305Encrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SODIUM_XCHACHA20POLY1305)
    return wCryptoSodiumXChacha20Poly1305Encrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SOFTWARE_XCHACHA20POLY1305)
    return wCryptoSoftwareXChacha20Poly1305Encrypt(dst, src, src_len, ad, ad_len, nonce, key);
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

int xchacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                             size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
#if defined(WCRYPTO_HAS_OPENSSL_XCHACHA20POLY1305)
    return wCryptoOpenSSLXChacha20Poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SODIUM_XCHACHA20POLY1305)
    return wCryptoSodiumXChacha20Poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
#elif defined(WCRYPTO_HAS_SOFTWARE_XCHACHA20POLY1305)
    return wCryptoSoftwareXChacha20Poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
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
