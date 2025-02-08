#include "wcrypto.h"
#include "wlibc.h"

#include "sodium.h"

// Encrypt function
int xchacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key)
{
    // Destination buffer must have space for ciphertext + authentication tag
    unsigned long long ciphertext_len = srclen + crypto_aead_xchacha20poly1305_ietf_ABYTES;

    // Perform encryption
    int result =
        crypto_aead_xchacha20poly1305_ietf_encrypt(dst, &ciphertext_len, src, srclen, ad, adlen, NULL, nonce, key);

    if (result != 0)
    {
        printError("Encryption failed\n");
        return -1;
    }

    return 0; // Success
}

// Decrypt function
int xchacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key)
{

    // Destination buffer must have space for plaintext
    unsigned long long plaintext_len = srclen - crypto_aead_xchacha20poly1305_ietf_ABYTES;

    // Perform decryption
    int result =
        crypto_aead_xchacha20poly1305_ietf_decrypt(dst, &plaintext_len, NULL, src, srclen, ad, adlen, nonce, key);

    if (result != 0)
    {
        printError("Decryption failed (possible tampering or invalid inputs)\n");
        return -1;
    }

    return 0; // Success
}
