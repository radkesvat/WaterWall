#include "wcrypto.h"



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

static bool can_run_aes256gcm_tests(void)
{
    if (wCryptoAes256GcmIsAvailable())
    {
        return true;
    }

    fprintf(stderr, "AES256-GCM is not available on this backend or CPU; skipping AES256-GCM unit cases.\n");
    return false;
}

/* NIST AES-256-GCM: zero key/IV, one zero plaintext block, no AAD. */
static void test_known_answer(void)
{
    const uint8_t key[AES256GCM_KEY_SIZE]                          = {0};
    const uint8_t nonce[AES256GCM_NONCE_SIZE]                      = {0};
    const uint8_t plaintext[16]                                    = {0};
    const uint8_t expected[sizeof(plaintext) + AES256GCM_TAG_SIZE] = {
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    };
    uint8_t ciphertext[sizeof(expected)] = {0};
    uint8_t decrypted[sizeof(plaintext)] = {0};

    require(wCryptoAes256GcmEncrypt(
                ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext), NULL, 0, nonce, key) == kWCryptoOk,
            "AES-256-GCM known-answer encryption failed");
    require(memcmp(ciphertext, expected, sizeof(expected)) == 0, "AES-256-GCM known-answer ciphertext/tag mismatch");
    require(wCryptoAes256GcmDecrypt(decrypted, sizeof(decrypted), expected, sizeof(expected), NULL, 0, nonce, key) ==
                kWCryptoOk,
            "AES-256-GCM known-answer decryption failed");
    require(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0, "AES-256-GCM known-answer plaintext mismatch");
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

    wcrypto_status_t res = wCryptoAes256GcmEncrypt(
        ciphertext, sizeof(ciphertext), plaintext, plaintext_len, associated_data, sizeof(associated_data), nonce, key);
    require(res == kWCryptoOk, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = wCryptoAes256GcmDecrypt(decrypted,
                                  sizeof(decrypted),
                                  ciphertext,
                                  sizeof(ciphertext),
                                  associated_data,
                                  sizeof(associated_data),
                                  nonce,
                                  key);

    require(res == kWCryptoOk, "Decryption failed");
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

    wcrypto_status_t res =
        wCryptoAes256GcmEncrypt(ciphertext, sizeof(ciphertext), plaintext, plaintext_len, NULL, 0, nonce, key);
    require(res == kWCryptoOk, "Encryption with empty AD failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = wCryptoAes256GcmDecrypt(decrypted, sizeof(decrypted), ciphertext, sizeof(ciphertext), NULL, 0, nonce, key);

    require(res == kWCryptoOk, "Decryption with empty AD failed");
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

    wcrypto_status_t res =
        wCryptoAes256GcmEncrypt(ciphertext, sizeof(ciphertext), plaintext, plaintext_len, NULL, 0, nonce, key);
    require(res == kWCryptoOk, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    memset(decrypted, 0xa5, sizeof(decrypted));
    res = wCryptoAes256GcmDecrypt(
        decrypted, sizeof(decrypted), ciphertext, sizeof(ciphertext), NULL, 0, nonce, wrong_key);

    require(res == kWCryptoAuthenticationFailed, "wrong-key status mismatch");
    require(decrypted[0] == 0 && decrypted[1] == 0 && decrypted[2] == 0, "wrong-key plaintext was not cleared");
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

    wcrypto_status_t res = wCryptoAes256GcmEncrypt(
        ciphertext, sizeof(ciphertext), plaintext, plaintext_len, associated_data, sizeof(associated_data), nonce, key);
    require(res == kWCryptoOk, "Encryption failed");

    uint8_t decrypted[sizeof(plaintext)];
    res = wCryptoAes256GcmDecrypt(decrypted,
                                  sizeof(decrypted),
                                  ciphertext,
                                  sizeof(ciphertext),
                                  wrong_associated_data,
                                  sizeof(wrong_associated_data),
                                  nonce,
                                  key);

    require(res == kWCryptoAuthenticationFailed, "wrong-AD status mismatch");
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

    wcrypto_status_t res =
        wCryptoAes256GcmEncrypt(ciphertext, sizeof(ciphertext), plaintext, plaintext_len, NULL, 0, nonce, key);
    require(res == kWCryptoOk, "Encryption failed");

    ciphertext[0] ^= 0x01;

    uint8_t decrypted[sizeof(plaintext)];
    res = wCryptoAes256GcmDecrypt(decrypted, sizeof(decrypted), ciphertext, sizeof(ciphertext), NULL, 0, nonce, key);

    require(res == kWCryptoAuthenticationFailed, "tampered-ciphertext status mismatch");
}

int main(void)
{
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization failed");
    if (! can_run_aes256gcm_tests())
    {
        wCryptoGlobalCleanup();
        return 0;
    }

    test_known_answer();
    test_encryption_decryption();
    test_encryption_decryption_empty_ad();
    test_decryption_failure_wrong_key();
    test_decryption_failure_wrong_ad();
    test_decryption_failure_tampered_ciphertext();
    wCryptoGlobalCleanup();
    return 0;
}
