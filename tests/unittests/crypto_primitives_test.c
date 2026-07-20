#include "wcrypto.h"
#include "private/crypto_backends.h"

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

typedef int (*aead_fn_t)(unsigned char *dst, const unsigned char *src, size_t src_len,
                         const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                         const unsigned char *key);

typedef struct aead_backend_s
{
    const char *name;
    aead_fn_t   encrypt;
    aead_fn_t   decrypt;
} aead_backend_t;

static const aead_backend_t chacha20poly1305_backends[] = {
    {"public dispatcher", chacha20poly1305Encrypt, chacha20poly1305Decrypt},
#if defined(WCRYPTO_HAS_SOFTWARE_CHACHA20POLY1305)
    {"software", wCryptoSoftwareChacha20Poly1305Encrypt, wCryptoSoftwareChacha20Poly1305Decrypt},
#endif
#if defined(WCRYPTO_HAS_OPENSSL_CHACHA20POLY1305)
    {"OpenSSL", wCryptoOpenSSLChacha20Poly1305Encrypt, wCryptoOpenSSLChacha20Poly1305Decrypt},
#endif
#if defined(WCRYPTO_HAS_SODIUM_CHACHA20POLY1305)
    {"libsodium", wCryptoSodiumChacha20Poly1305Encrypt, wCryptoSodiumChacha20Poly1305Decrypt},
#endif
};

static const aead_backend_t xchacha20poly1305_backends[] = {
    {"public dispatcher", xchacha20poly1305Encrypt, xchacha20poly1305Decrypt},
#if defined(WCRYPTO_HAS_SOFTWARE_XCHACHA20POLY1305)
    {"software", wCryptoSoftwareXChacha20Poly1305Encrypt, wCryptoSoftwareXChacha20Poly1305Decrypt},
#endif
#if defined(WCRYPTO_HAS_OPENSSL_XCHACHA20POLY1305)
    {"OpenSSL", wCryptoOpenSSLXChacha20Poly1305Encrypt, wCryptoOpenSSLXChacha20Poly1305Decrypt},
#endif
#if defined(WCRYPTO_HAS_SODIUM_XCHACHA20POLY1305)
    {"libsodium", wCryptoSodiumXChacha20Poly1305Encrypt, wCryptoSodiumXChacha20Poly1305Decrypt},
#endif
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

static void require_backend(bool condition, const char *backend, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s: %s\n", backend, message);
        exit(1);
    }
}

static void require_backend_bytes_equal(const uint8_t *actual, const uint8_t *expected, size_t len,
                                        const char *backend, const char *message)
{
    require_backend(wCryptoEqual(actual, expected, len), backend, message);
}

static void initialize_crypto_backend(void)
{
#if defined(WCRYPTO_BACKEND_SODIUM)
    require(sodium_init() != -1, "sodium_init failed");
#endif
}

static void test_hash_vectors(void)
{
    const uint8_t input[] = "abc";
    const uint8_t expected_md5[MD5_DIGEST_SIZE] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    };
    const uint8_t expected_sha1[SHA1_DIGEST_SIZE] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    };
    const uint8_t expected_sha224[SHA224_DIGEST_SIZE] = {
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42,
        0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4,
        0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
    };
    const uint8_t expected_sha256[SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    md5_hash_t    md5    = {0};
    sha1_hash_t   sha1   = {0};
    sha224_hash_t sha224 = {0};
    sha256_hash_t sha256 = {0};

    require(wCryptoMD5(&md5, input, sizeof(input) - 1) == 0, "MD5 failed");
    require_bytes_equal(md5.bytes, expected_md5, sizeof(expected_md5), "MD5 vector mismatch");

    require(wCryptoSHA1(&sha1, input, sizeof(input) - 1) == 0, "SHA1 failed");
    require_bytes_equal(sha1.bytes, expected_sha1, sizeof(expected_sha1), "SHA1 vector mismatch");

    require(wCryptoSHA224(&sha224, input, sizeof(input) - 1) == 0, "SHA224 failed");
    require_bytes_equal(sha224.bytes, expected_sha224, sizeof(expected_sha224), "SHA224 vector mismatch");

    require(wCryptoSHA256(&sha256, input, sizeof(input) - 1) == 0, "SHA256 failed");
    require_bytes_equal(sha256.bytes, expected_sha256, sizeof(expected_sha256), "SHA256 vector mismatch");
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

static void test_chacha20poly1305_nonzero_prefix_and_interoperability(void)
{
    const uint8_t plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e,
    };
    const uint8_t ad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    };
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    const uint8_t expected[sizeof(plaintext) + POLY1305_TAG_SIZE] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
        0x06, 0x91,
    };
    uint8_t outputs[sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0])][sizeof(expected)];
    uint8_t decrypted[sizeof(plaintext)];
    const size_t backend_count = sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]);

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        const aead_backend_t *backend = &chacha20poly1305_backends[producer];
        require_backend(backend->encrypt(outputs[producer], plaintext, sizeof(plaintext), ad, sizeof(ad), nonce, key) == 0,
                        backend->name, "RFC 8439 encryption failed");
        require_backend_bytes_equal(outputs[producer], expected, sizeof(expected), backend->name,
                                    "RFC 8439 ciphertext/tag mismatch");
    }

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        for (size_t consumer = 0; consumer < backend_count; ++consumer)
        {
            const aead_backend_t *backend = &chacha20poly1305_backends[consumer];
            memoryZero(decrypted, sizeof(decrypted));
            require_backend(backend->decrypt(decrypted, outputs[producer], sizeof(expected), ad, sizeof(ad), nonce, key) == 0,
                            backend->name, "cross-backend RFC 8439 decryption failed");
            require_backend_bytes_equal(decrypted, plaintext, sizeof(plaintext), backend->name,
                                        "cross-backend RFC 8439 plaintext mismatch");
        }
    }
}

static void test_chacha20poly1305_nonce_prefix_sensitivity(void)
{
    const uint8_t plaintext[] = "nonce-prefix-sensitivity";
    const uint8_t ad[] = "nonce-prefix-aad";
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE] = {0x42};
    const uint8_t nonce_a[CHACHA20POLY1305_NONCE_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    const uint8_t nonce_b[CHACHA20POLY1305_NONCE_SIZE] = {
        0x05, 0x06, 0x07, 0x08, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    uint8_t ciphertext_a[sizeof(plaintext) - 1 + POLY1305_TAG_SIZE];
    uint8_t ciphertext_b[sizeof(ciphertext_a)];
    uint8_t decrypted[sizeof(plaintext) - 1];
    const size_t backend_count = sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]);

    for (size_t i = 0; i < backend_count; ++i)
    {
        const aead_backend_t *backend = &chacha20poly1305_backends[i];
        require_backend(backend->encrypt(ciphertext_a, plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1,
                                         nonce_a, key) == 0,
                        backend->name, "nonce A encryption failed");
        require_backend(backend->encrypt(ciphertext_b, plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1,
                                         nonce_b, key) == 0,
                        backend->name, "nonce B encryption failed");
        require_backend(! wCryptoEqual(ciphertext_a, ciphertext_b, sizeof(ciphertext_a)), backend->name,
                        "changing nonce bytes 0-3 did not change ciphertext/tag");

        require_backend(backend->decrypt(decrypted, ciphertext_a, sizeof(ciphertext_a), ad, sizeof(ad) - 1,
                                         nonce_a, key) == 0,
                        backend->name, "matching nonce A decryption failed");
        require_backend_bytes_equal(decrypted, plaintext, sizeof(decrypted), backend->name,
                                    "matching nonce A plaintext mismatch");
        require_backend(backend->decrypt(decrypted, ciphertext_b, sizeof(ciphertext_b), ad, sizeof(ad) - 1,
                                         nonce_b, key) == 0,
                        backend->name, "matching nonce B decryption failed");
        require_backend_bytes_equal(decrypted, plaintext, sizeof(decrypted), backend->name,
                                    "matching nonce B plaintext mismatch");
        require_backend(backend->decrypt(decrypted, ciphertext_a, sizeof(ciphertext_a), ad, sizeof(ad) - 1,
                                         nonce_b, key) != 0,
                        backend->name, "wrong nonce prefix authenticated");
        require_backend(backend->decrypt(decrypted, ciphertext_b, sizeof(ciphertext_b), ad, sizeof(ad) - 1,
                                         nonce_a, key) != 0,
                        backend->name, "reverse wrong nonce prefix authenticated");
    }
}

static void test_aead_short_ciphertexts(const aead_backend_t *backends, size_t backend_count,
                                        const uint8_t *nonce)
{
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE] = {0};
    const uint8_t empty_plaintext = 0;
    uint8_t ciphertext[POLY1305_TAG_SIZE] = {0};
    uint8_t decrypted = 0;

    for (size_t backend_index = 0; backend_index < backend_count; ++backend_index)
    {
        const aead_backend_t *backend = &backends[backend_index];

        for (size_t ciphertext_len = 0; ciphertext_len < POLY1305_TAG_SIZE; ++ciphertext_len)
        {
            require_backend(backend->decrypt(&decrypted, ciphertext, ciphertext_len, NULL, 0, nonce, key) != 0,
                            backend->name, "short AEAD ciphertext was accepted");
        }

        require_backend(backend->encrypt(ciphertext, &empty_plaintext, 0, NULL, 0, nonce, key) == 0,
                        backend->name, "empty AEAD plaintext encryption failed");
        require_backend(backend->decrypt(&decrypted, ciphertext, sizeof(ciphertext), NULL, 0, nonce, key) == 0,
                        backend->name, "tag-only AEAD ciphertext was rejected");
    }
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
    uint8_t outputs[sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0])][sizeof(expected)];
    uint8_t decrypted[sizeof(plaintext) - 1] = {0};
    const size_t backend_count = sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0]);

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        const aead_backend_t *backend = &xchacha20poly1305_backends[producer];
        require_backend(backend->encrypt(outputs[producer], (const uint8_t *) plaintext, sizeof(plaintext) - 1,
                                         (const uint8_t *) ad, sizeof(ad) - 1, nonce, key) == 0,
                        backend->name, "XChaCha20-Poly1305 encryption failed");
        require_backend_bytes_equal(outputs[producer], expected, sizeof(expected), backend->name,
                                    "XChaCha20-Poly1305 vector mismatch");
    }

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        for (size_t consumer = 0; consumer < backend_count; ++consumer)
        {
            const aead_backend_t *backend = &xchacha20poly1305_backends[consumer];
            memoryZero(decrypted, sizeof(decrypted));
            require_backend(backend->decrypt(decrypted, outputs[producer], sizeof(expected), (const uint8_t *) ad,
                                             sizeof(ad) - 1, nonce, key) == 0,
                            backend->name, "cross-backend XChaCha20-Poly1305 decryption failed");
            require_backend_bytes_equal(decrypted, (const uint8_t *) plaintext, sizeof(decrypted), backend->name,
                                        "cross-backend XChaCha20-Poly1305 plaintext mismatch");
        }
    }
}

int main(void)
{
    const uint8_t chacha_nonce[CHACHA20POLY1305_NONCE_SIZE] = {0};
    const uint8_t xchacha_nonce[XCHACHA20POLY1305_NONCE_SIZE] = {0};

    initialize_crypto_backend();

    test_hash_vectors();
    test_blake2s_unkeyed();
    test_blake2s_keyed();
    test_x25519();
    test_chacha20poly1305();
    test_chacha20poly1305_nonzero_prefix_and_interoperability();
    test_chacha20poly1305_nonce_prefix_sensitivity();
    test_aead_short_ciphertexts(chacha20poly1305_backends,
                                sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]),
                                chacha_nonce);
    test_xchacha20poly1305();
    test_aead_short_ciphertexts(xchacha20poly1305_backends,
                                sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0]),
                                xchacha_nonce);
    return 0;
}
