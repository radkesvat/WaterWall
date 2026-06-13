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
    BLAKE2S_DIGEST_SIZE = 32,
    X25519_KEY_SIZE = 32,
    CHACHA20POLY1305_KEY_SIZE = 32,
    CHACHA20POLY1305_NONCE_SIZE = 12,
    XCHACHA20POLY1305_NONCE_SIZE = 24,
    POLY1305_TAG_SIZE = 16,
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void require_bytes_equal(const uint8_t *actual, const uint8_t *expected, size_t len, const char *message)
{
    if (! wCryptoEqual(actual, expected, len))
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

static void test_blake2s_unkeyed(void)
{
    const uint8_t input[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    const uint8_t expected[BLAKE2S_DIGEST_SIZE] = {
        0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35,
        0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72,
        0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
    };
    uint8_t output[BLAKE2S_DIGEST_SIZE] = {0};

    require(blake2s(output, sizeof(output), NULL, 0, input, sizeof(input) - 1) == 0, "BLAKE2s failed");
    require_bytes_equal(output, expected, sizeof(output), "BLAKE2s unkeyed vector mismatch");
}

static void test_blake2s_keyed(void)
{
    const uint8_t input[] = "Salam farmande! seyed ali dahe 80 hasho fara khande!";
    const uint8_t key[] = {0x00, 0x01, 0x02, 0x03};
    const uint8_t expected[BLAKE2S_DIGEST_SIZE] = {
        0xf5, 0xae, 0x22, 0xd5, 0xd5, 0x5f, 0xb3, 0x1e, 0x5c, 0xf2, 0x61,
        0x99, 0x9c, 0x2f, 0x5d, 0x88, 0x95, 0xb3, 0xf2, 0x02, 0x32, 0x57,
        0x19, 0x61, 0x43, 0x9e, 0xcf, 0x58, 0x6e, 0x58, 0x48, 0xed,
    };
    uint8_t output[BLAKE2S_DIGEST_SIZE] = {0};

    require(blake2s(output, sizeof(output), key, sizeof(key), input, sizeof(input) - 1) == 0, "Keyed BLAKE2s failed");
    require_bytes_equal(output, expected, sizeof(output), "BLAKE2s keyed vector mismatch");
}

static void test_x25519(void)
{
    const uint8_t scalar[X25519_KEY_SIZE] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
        0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
        0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const uint8_t point[X25519_KEY_SIZE] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
        0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
        0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    };
    const uint8_t expected[X25519_KEY_SIZE] = {
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
        0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
        0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    };
    uint8_t shared_secret[X25519_KEY_SIZE] = {0};

    require(performX25519(shared_secret, scalar, point) == 0, "X25519 failed");
    require_bytes_equal(shared_secret, expected, sizeof(shared_secret), "X25519 vector mismatch");
}

static void test_chacha20poly1305(void)
{
    const char plaintext[] = "This is a secret message!";
    const char ad[] = "Additional authenticated data";
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE] = {0x00};
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE] = {0, 0, 0, 0, 88, 90, 07, 1, 2, 3, 4, 8};
    const uint8_t expected[(sizeof(plaintext) - 1) + POLY1305_TAG_SIZE] = {
        0x88, 0x10, 0xcc, 0x6b, 0xc6, 0x12, 0xb2, 0xe3, 0x71, 0xf9, 0x9a,
        0x1e, 0xed, 0x2b, 0x87, 0x27, 0x50, 0x1d, 0x2a, 0xba, 0xf0, 0x77,
        0x03, 0xb6, 0x63, 0x16, 0x50, 0xd2, 0x52, 0x5b, 0x16, 0xb7, 0x18,
        0xd8, 0x8e, 0x24, 0x51, 0x67, 0x41, 0xb7, 0x1e,
    };
    uint8_t ciphertext[sizeof(expected)] = {0};
    uint8_t decrypted[sizeof(plaintext) - 1] = {0};

    require(chacha20poly1305Encrypt(ciphertext,
                                    (const uint8_t *) plaintext,
                                    sizeof(plaintext) - 1,
                                    (const uint8_t *) ad,
                                    sizeof(ad) - 1,
                                    nonce,
                                    key) == 0,
            "ChaCha20-Poly1305 encryption failed");
    require_bytes_equal(ciphertext, expected, sizeof(ciphertext), "ChaCha20-Poly1305 vector mismatch");

    require(chacha20poly1305Decrypt(decrypted, ciphertext, sizeof(ciphertext), (const uint8_t *) ad, sizeof(ad) - 1,
                                    nonce, key) == 0,
            "ChaCha20-Poly1305 decryption failed");
    require_bytes_equal(decrypted, (const uint8_t *) plaintext, sizeof(decrypted), "ChaCha20-Poly1305 round trip failed");
}

static void test_xchacha20poly1305(void)
{
    const char plaintext[] = "This is a secret message!";
    const char ad[] = "Additional authenticated data";
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE] = {0x00};
    const uint8_t nonce[XCHACHA20POLY1305_NONCE_SIZE] = {0x01};
    const uint8_t expected[(sizeof(plaintext) - 1) + POLY1305_TAG_SIZE] = {
        0x3e, 0x51, 0x7a, 0xb2, 0xdf, 0x97, 0x45, 0x79, 0x36, 0xe7, 0x86,
        0xf3, 0x96, 0x0c, 0xda, 0x04, 0x3c, 0x9b, 0x3f, 0x38, 0xdd, 0xce,
        0x59, 0x2b, 0x49, 0xd4, 0x0f, 0x6e, 0x19, 0x66, 0xb7, 0x36, 0x32,
        0x87, 0x5a, 0x73, 0x5f, 0x00, 0xb1, 0xb7, 0x3e,
    };
    uint8_t ciphertext[sizeof(expected)] = {0};
    uint8_t decrypted[sizeof(plaintext) - 1] = {0};

    require(xchacha20poly1305Encrypt(ciphertext,
                                     (const uint8_t *) plaintext,
                                     sizeof(plaintext) - 1,
                                     (const uint8_t *) ad,
                                     sizeof(ad) - 1,
                                     nonce,
                                     key) == 0,
            "XChaCha20-Poly1305 encryption failed");
    require_bytes_equal(ciphertext, expected, sizeof(ciphertext), "XChaCha20-Poly1305 vector mismatch");

    require(xchacha20poly1305Decrypt(decrypted, ciphertext, sizeof(ciphertext), (const uint8_t *) ad, sizeof(ad) - 1,
                                     nonce, key) == 0,
            "XChaCha20-Poly1305 decryption failed");
    require_bytes_equal(decrypted, (const uint8_t *) plaintext, sizeof(decrypted),
                        "XChaCha20-Poly1305 round trip failed");
}

int main(void)
{
    initialize_crypto_backend();

    test_blake2s_unkeyed();
    test_blake2s_keyed();
    test_x25519();
    test_chacha20poly1305();
    test_xchacha20poly1305();
    return 0;
}
