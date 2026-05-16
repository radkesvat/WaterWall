#include "wcrypto.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WCRYPTO_BACKEND_SODIUM)
#include <sodium.h>
#endif

enum
{
    AES256GCM_KEY_SIZE   = 32,
    AES256GCM_NONCE_SIZE = 12,
    AES256GCM_TAG_SIZE   = 16,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void initialize_crypto_backend(void)
{
#if defined(WCRYPTO_BACKEND_SODIUM)
    require(sodium_init() != -1, "sodium_init failed");
#endif
}

static bool can_run_aes256gcm_tests(void)
{
    if (aes256gcmIsAvailable())
    {
        return true;
    }

    fprintf(stderr, "AES256-GCM is not available on this backend or CPU; skipping AES256-GCM unit cases.\n");
    return false;
}

/* Verifies a normal authenticated encryption round trip with associated data. */
static void test_encryption_decryption(void)
{
    uint8_t key[AES256GCM_KEY_SIZE];
    memset(key, 0xAA, sizeof(key));

    uint8_t nonce[AES256GCM_NONCE_SIZE];
    memset(nonce, 0xBB, sizeof(nonce));

    uint8_t associated_data[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t plaintext[]       = {0xDE, 0xAD, 0xBE, 0xEF};

    const size_t plaintext_len = sizeof(plaintext);
    uint8_t      ciphertext[sizeof(plaintext) + AES256GCM_TAG_SIZE];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len, associated_data, sizeof(associated_data), nonce,
                               key);
    require(res == 0, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext), associated_data, sizeof(associated_data), nonce,
                           key);

    require(res == 0, "Decryption failed");
    require(memcmp(decrypted, plaintext, plaintext_len) == 0, "Decrypted text does not match plaintext");
}

/* Verifies that a NULL/zero-length associated-data pair is accepted. */
static void test_encryption_decryption_empty_ad(void)
{
    uint8_t key[AES256GCM_KEY_SIZE];
    memset(key, 0xCC, sizeof(key));

    uint8_t nonce[AES256GCM_NONCE_SIZE];
    memset(nonce, 0xDD, sizeof(nonce));

    uint8_t plaintext[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    const size_t plaintext_len = sizeof(plaintext);
    uint8_t      ciphertext[sizeof(plaintext) + AES256GCM_TAG_SIZE];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len, NULL, 0, nonce, key);
    require(res == 0, "Encryption with empty AD failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext), NULL, 0, nonce, key);

    require(res == 0, "Decryption with empty AD failed");
    require(memcmp(decrypted, plaintext, plaintext_len) == 0, "Decrypted text does not match plaintext (empty AD)");
}

/* Verifies that authentication rejects a ciphertext when the key changes. */
static void test_decryption_failure_wrong_key(void)
{
    uint8_t key[AES256GCM_KEY_SIZE];
    memset(key, 0xEE, sizeof(key));

    uint8_t wrong_key[AES256GCM_KEY_SIZE];
    memset(wrong_key, 0xFF, sizeof(wrong_key));

    uint8_t nonce[AES256GCM_NONCE_SIZE];
    memset(nonce, 0x11, sizeof(nonce));

    uint8_t plaintext[] = {0x00, 0x11, 0x22};

    const size_t plaintext_len = sizeof(plaintext);
    uint8_t      ciphertext[sizeof(plaintext) + AES256GCM_TAG_SIZE];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len, NULL, 0, nonce, key);
    require(res == 0, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext), NULL, 0, nonce, wrong_key);

    require(res != 0, "Decryption should have failed with wrong key");
}

/* Verifies that associated data is part of the authentication decision. */
static void test_decryption_failure_wrong_ad(void)
{
    uint8_t key[AES256GCM_KEY_SIZE];
    memset(key, 0x77, sizeof(key));

    uint8_t nonce[AES256GCM_NONCE_SIZE];
    memset(nonce, 0x88, sizeof(nonce));

    uint8_t associated_data[]       = {0xAA, 0xBB};
    uint8_t wrong_associated_data[] = {0xAA, 0xCC};
    uint8_t plaintext[]             = {0x99};

    const size_t plaintext_len = sizeof(plaintext);
    uint8_t      ciphertext[sizeof(plaintext) + AES256GCM_TAG_SIZE];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len, associated_data, sizeof(associated_data), nonce,
                               key);
    require(res == 0, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext), wrong_associated_data,
                           sizeof(wrong_associated_data), nonce, key);

    require(res != 0, "Decryption should have failed with wrong AD");
}

/* Verifies that modifying ciphertext bytes invalidates the authentication tag. */
static void test_decryption_failure_tampered_ciphertext(void)
{
    uint8_t key[AES256GCM_KEY_SIZE];
    memset(key, 0x55, sizeof(key));

    uint8_t nonce[AES256GCM_NONCE_SIZE];
    memset(nonce, 0x66, sizeof(nonce));

    uint8_t plaintext[] = {0x12, 0x34, 0x56, 0x78};

    const size_t plaintext_len = sizeof(plaintext);
    uint8_t      ciphertext[sizeof(plaintext) + AES256GCM_TAG_SIZE];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len, NULL, 0, nonce, key);
    require(res == 0, "Encryption failed");

    ciphertext[0] ^= 0x01;

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext), NULL, 0, nonce, key);

    require(res != 0, "Decryption should have failed with tampered ciphertext");
}

int main(void)
{
    initialize_crypto_backend();
    if (! can_run_aes256gcm_tests())
    {
        return 0;
    }

    test_encryption_decryption();
    test_encryption_decryption_empty_ad();
    test_decryption_failure_wrong_key();
    test_decryption_failure_wrong_ad();
    test_decryption_failure_tampered_ciphertext();
    return 0;
}
