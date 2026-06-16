#include "private/crypto_backends.h"
#include "wlibc.h"

#include "sodium.h"

int wCryptoSodiumAES256GCMIsAvailable(void)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");
    return crypto_aead_aes256gcm_is_available();
}

int wCryptoSodiumAES256GCMEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                  const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                  const unsigned char *key)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");

    if (! crypto_aead_aes256gcm_is_available())
    {
        printError("aes256gcmEncrypt failed: AES256-GCM is unavailable on this CPU/backend\n");
        return -1;
    }

    unsigned long long ciphertext_len = 0;
    if (0 != crypto_aead_aes256gcm_encrypt(dst, &ciphertext_len, src, src_len, ad, ad_len, NULL, nonce, key))
    {
        printError("aes256gcmEncrypt failed\n");
        return -1;
    }

    return 0;
}

int wCryptoSodiumAES256GCMDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                  const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                  const unsigned char *key)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");

    if (! crypto_aead_aes256gcm_is_available())
    {
        printError("aes256gcmDecrypt failed: AES256-GCM is unavailable on this CPU/backend\n");
        return -1;
    }

    unsigned long long plaintext_len = 0;
    if (0 != crypto_aead_aes256gcm_decrypt(dst, &plaintext_len, NULL, src, src_len, ad, ad_len, nonce, key))
    {
        printError("aes256gcmDecrypt failed\n");
        return -1;
    }

    return 0;
}
