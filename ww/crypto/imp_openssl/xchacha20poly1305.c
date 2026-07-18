#include "private/crypto_backends.h"
#include "../impl_software/private/defs.h"

int wCryptoOpenSSLXChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen,
                                           const unsigned char *ad, size_t adlen, const unsigned char *nonce,
                                           const unsigned char *key)
{
    uint8_t subkey[CHACHA20_KEY_SIZE];
    uint8_t derived_nonce[CHACHA20_IETF_NONCE_SIZE] = {0};
    int     result;

    memoryCopy(derived_nonce + 4, nonce + 16, 8);
    hchacha20(subkey, nonce, key);
    result = wCryptoOpenSSLChacha20Poly1305Encrypt(dst, src, srclen, ad, adlen, derived_nonce, subkey);
    wCryptoZero(subkey, sizeof(subkey));
    wCryptoZero(derived_nonce, sizeof(derived_nonce));

    return result;
}

int wCryptoOpenSSLXChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen,
                                           const unsigned char *ad, size_t adlen, const unsigned char *nonce,
                                           const unsigned char *key)
{
    uint8_t subkey[CHACHA20_KEY_SIZE];
    uint8_t derived_nonce[CHACHA20_IETF_NONCE_SIZE] = {0};
    int     result;

    memoryCopy(derived_nonce + 4, nonce + 16, 8);
    hchacha20(subkey, nonce, key);
    result = wCryptoOpenSSLChacha20Poly1305Decrypt(dst, src, srclen, ad, adlen, derived_nonce, subkey);
    wCryptoZero(subkey, sizeof(subkey));
    wCryptoZero(derived_nonce, sizeof(derived_nonce));

    return result;
}
