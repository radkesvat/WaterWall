#include "wcrypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void test_encryption_decryption(void)
{
    // If not available, we can't test it, but it should return 0 so it passes gracefully.
    if (!aes256gcmIsAvailable()) {
        fprintf(stderr, "AES256-GCM is not available, skipping test.\n");
        return;
    }

    uint8_t key[32];
    memset(key, 0xAA, sizeof(key));
    uint8_t nonce[12];
    memset(nonce, 0xBB, sizeof(nonce));
    uint8_t ad[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t plaintext[] = {0xDE, 0xAD, 0xBE, 0xEF};

    // Ciphertext size = plaintext size + 16 bytes auth tag
    size_t plaintext_len = sizeof(plaintext);
    uint8_t ciphertext[sizeof(plaintext) + 16];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len,
                               ad, sizeof(ad), nonce, key);
    require(res == 0, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext),
                           ad, sizeof(ad), nonce, key);

    require(res == 0, "Decryption failed");
    require(memcmp(decrypted, plaintext, plaintext_len) == 0, "Decrypted text does not match plaintext");
}

static void test_encryption_decryption_empty_ad(void)
{
    if (!aes256gcmIsAvailable()) {
        return;
    }

    uint8_t key[32];
    memset(key, 0xCC, sizeof(key));
    uint8_t nonce[12];
    memset(nonce, 0xDD, sizeof(nonce));
    uint8_t plaintext[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    size_t plaintext_len = sizeof(plaintext);
    uint8_t ciphertext[sizeof(plaintext) + 16];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len,
                               NULL, 0, nonce, key);
    require(res == 0, "Encryption with empty AD failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext),
                           NULL, 0, nonce, key);

    require(res == 0, "Decryption with empty AD failed");
    require(memcmp(decrypted, plaintext, plaintext_len) == 0, "Decrypted text does not match plaintext (empty AD)");
}

static void test_decryption_failure_wrong_key(void)
{
    if (!aes256gcmIsAvailable()) {
        return;
    }

    uint8_t key[32];
    memset(key, 0xEE, sizeof(key));
    uint8_t wrong_key[32];
    memset(wrong_key, 0xFF, sizeof(wrong_key));

    uint8_t nonce[12];
    memset(nonce, 0x11, sizeof(nonce));
    uint8_t plaintext[] = {0x00, 0x11, 0x22};

    size_t plaintext_len = sizeof(plaintext);
    uint8_t ciphertext[sizeof(plaintext) + 16];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len,
                               NULL, 0, nonce, key);
    require(res == 0, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext),
                           NULL, 0, nonce, wrong_key);

    require(res != 0, "Decryption should have failed with wrong key");
}

static void test_decryption_failure_wrong_ad(void)
{
    if (!aes256gcmIsAvailable()) {
        return;
    }

    uint8_t key[32];
    memset(key, 0x77, sizeof(key));

    uint8_t nonce[12];
    memset(nonce, 0x88, sizeof(nonce));

    uint8_t ad[] = {0xAA, 0xBB};
    uint8_t wrong_ad[] = {0xAA, 0xCC};

    uint8_t plaintext[] = {0x99};

    size_t plaintext_len = sizeof(plaintext);
    uint8_t ciphertext[sizeof(plaintext) + 16];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len,
                               ad, sizeof(ad), nonce, key);
    require(res == 0, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext),
                           wrong_ad, sizeof(wrong_ad), nonce, key);

    require(res != 0, "Decryption should have failed with wrong AD");
}

static void test_decryption_failure_tampered_ciphertext(void)
{
    if (!aes256gcmIsAvailable()) {
        return;
    }

    uint8_t key[32];
    memset(key, 0x55, sizeof(key));

    uint8_t nonce[12];
    memset(nonce, 0x66, sizeof(nonce));

    uint8_t plaintext[] = {0x12, 0x34, 0x56, 0x78};

    size_t plaintext_len = sizeof(plaintext);
    uint8_t ciphertext[sizeof(plaintext) + 16];

    int res = aes256gcmEncrypt(ciphertext, plaintext, plaintext_len,
                               NULL, 0, nonce, key);
    require(res == 0, "Encryption failed");

    // Tamper with the ciphertext
    ciphertext[0] ^= 0x01;

    uint8_t decrypted[sizeof(plaintext)];
    res = aes256gcmDecrypt(decrypted, ciphertext, sizeof(ciphertext),
                           NULL, 0, nonce, key);

    require(res != 0, "Decryption should have failed with tampered ciphertext");
}

int main(void)
{
    require(sodium_init() != -1, "sodium_init failed");

    test_encryption_decryption();
    test_encryption_decryption_empty_ad();
    test_decryption_failure_wrong_key();
    test_decryption_failure_wrong_ad();
    test_decryption_failure_tampered_ciphertext();
    return 0;
}
