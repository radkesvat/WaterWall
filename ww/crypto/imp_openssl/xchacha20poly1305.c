#include "private/crypto_backends.h"
#include "../impl_software/private/defs.h"

int wCryptoOpenSSLXChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen,
                                           const unsigned char *ad, size_t adlen, const unsigned char *nonce,
                                           const unsigned char *key)
{
    uint8_t  subkey[CHACHA20_KEY_SIZE];
    uint64_t new_nonce = U8TO64_LITTLE(nonce + 16);
    uint32_t derived_nonce[3] = {0, (uint32_t)(new_nonce & 0xFFFFFFFFULL), (uint32_t)(new_nonce >> 32)};
    int      result;

    hchacha20(subkey, nonce, key);
    result =
        wCryptoOpenSSLChacha20Poly1305Encrypt(dst, src, srclen, ad, adlen, (const unsigned char *) derived_nonce, subkey);
    wCryptoZero(subkey, sizeof(subkey));

    return result;
}

int wCryptoOpenSSLXChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen,
                                           const unsigned char *ad, size_t adlen, const unsigned char *nonce,
                                           const unsigned char *key)
{
    uint8_t  subkey[CHACHA20_KEY_SIZE];
    uint64_t new_nonce = U8TO64_LITTLE(nonce + 16);
    uint32_t derived_nonce[3] = {0, (uint32_t)(new_nonce & 0xFFFFFFFFULL), (uint32_t)(new_nonce >> 32)};
    int      result;

    hchacha20(subkey, nonce, key);
    result =
        wCryptoOpenSSLChacha20Poly1305Decrypt(dst, src, srclen, ad, adlen, (const unsigned char *) derived_nonce, subkey);
    wCryptoZero(subkey, sizeof(subkey));

    return result;
}
