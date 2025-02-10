#include "wcrypto.h"
#include "wlibc.h"

#include "sodium.h"

// Helper function for encryption using EVP API
int chacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                            size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");

    // Buffer to store the ciphertext and authentication tag
    unsigned long long ciphertext_len = 0;

    // Perform encryption
    if (0 != crypto_aead_chacha20poly1305_ietf_encrypt(dst, &ciphertext_len, src, srclen, ad, adlen, NULL, nonce, key))
    {
        printError("chacha20poly1305Encrypt failed\n");
        return -1;
    }

    // Return the total length of ciphertext + tag
    // return (int) ciphertext_len;
    return 0;
}

// Helper function for decryption using EVP API
int chacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                            size_t adlen, const unsigned char *nonce, const unsigned char *key)
{

    assert(sodium_init() != -1 && "libsodium must be initialized before calling this function");

    // Buffer to store the decrypted plaintext
    unsigned long long plaintext_len = 0;

    // Perform decryption
    if (0 != crypto_aead_chacha20poly1305_ietf_decrypt(dst, &plaintext_len, NULL, src, srclen, ad, adlen, nonce, key))
    {
        // "Decryption failed or authentication tag verification failed
        printError("chacha20poly1305Decrypt failed\n");

        return -1;
    }

    // Return the length of the decrypted plaintext
    // return (int) plaintext_len;
    return 0;
}
