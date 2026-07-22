#include "private/crypto_backends.h"
#include "wcrypto.h"



enum
{
    BLAKE2S_DIGEST_SIZE                  = 32,
    X25519_KEY_SIZE                      = 32,
    CHACHA20POLY1305_KEY_SIZE            = 32,
    CHACHA20POLY1305_NONCE_SIZE          = 12,
    XCHACHA20POLY1305_NONCE_SIZE         = 24,
    POLY1305_TAG_SIZE                    = 16,
    ENCRYPTION_RUNTIME_MAX_FRAME_PAYLOAD = 16384 - 12 - POLY1305_TAG_SIZE,
};

typedef wcrypto_status_t (*aead_fn_t)(unsigned char *dst, size_t dst_capacity, const unsigned char *src, size_t src_len,
                                      const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                      const unsigned char *key);

typedef struct aead_backend_s
{
    const char *name;
    aead_fn_t   encrypt;
    aead_fn_t   decrypt;
    bool (*is_available)(void);
} aead_backend_t;

typedef wcrypto_status_t (*x25519_fn_t)(unsigned char *, const unsigned char *, const unsigned char *);

typedef struct x25519_backend_s
{
    const char *name;
    x25519_fn_t derive;
} x25519_backend_t;

static const aead_backend_t chacha20poly1305_backends[] = {
    {"public dispatcher", wCryptoChaCha20Poly1305Encrypt, wCryptoChaCha20Poly1305Decrypt, NULL},
#if defined(WCRYPTO_HAS_SOFTWARE_CHACHA20POLY1305)
    {"software", wCryptoSoftwareChacha20Poly1305Encrypt, wCryptoSoftwareChacha20Poly1305Decrypt, NULL},
#endif
#if defined(WCRYPTO_HAS_OPENSSL_CHACHA20POLY1305)
    {"OpenSSL", wCryptoOpenSSLChacha20Poly1305Encrypt, wCryptoOpenSSLChacha20Poly1305Decrypt, NULL},
#endif
#if defined(WCRYPTO_HAS_SODIUM_CHACHA20POLY1305)
    {"libsodium", wCryptoSodiumChacha20Poly1305Encrypt, wCryptoSodiumChacha20Poly1305Decrypt, NULL},
#endif
};

static const aead_backend_t xchacha20poly1305_backends[] = {
    {"public dispatcher", wCryptoXChaCha20Poly1305Encrypt, wCryptoXChaCha20Poly1305Decrypt, NULL},
#if defined(WCRYPTO_HAS_SOFTWARE_XCHACHA20POLY1305)
    {"software", wCryptoSoftwareXChacha20Poly1305Encrypt, wCryptoSoftwareXChacha20Poly1305Decrypt, NULL},
#endif
#if defined(WCRYPTO_HAS_OPENSSL_XCHACHA20POLY1305)
    {"OpenSSL", wCryptoOpenSSLXChacha20Poly1305Encrypt, wCryptoOpenSSLXChacha20Poly1305Decrypt, NULL},
#endif
#if defined(WCRYPTO_HAS_SODIUM_XCHACHA20POLY1305)
    {"libsodium", wCryptoSodiumXChacha20Poly1305Encrypt, wCryptoSodiumXChacha20Poly1305Decrypt, NULL},
#endif
};

static const aead_backend_t aes256gcm_backends[] = {
    {"public dispatcher", wCryptoAes256GcmEncrypt, wCryptoAes256GcmDecrypt, wCryptoAes256GcmIsAvailable},
#if defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
    {"software", wCryptoSoftwareAES256GCMEncrypt, wCryptoSoftwareAES256GCMDecrypt, wCryptoSoftwareAES256GCMIsAvailable},
#endif
#if defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
    {"OpenSSL", wCryptoOpenSSLAES256GCMEncrypt, wCryptoOpenSSLAES256GCMDecrypt, wCryptoOpenSSLAES256GCMIsAvailable},
#endif
#if defined(WCRYPTO_HAS_SODIUM_AES256GCM)
    {"libsodium", wCryptoSodiumAES256GCMEncrypt, wCryptoSodiumAES256GCMDecrypt, wCryptoSodiumAES256GCMIsAvailable},
#endif
};

static const x25519_backend_t x25519_backends[] = {
    {"public dispatcher", wCryptoX25519},
#if defined(WCRYPTO_HAS_SOFTWARE_X25519)
    {"software", wCryptoSoftwareX25519},
#endif
#if defined(WCRYPTO_HAS_OPENSSL_X25519)
    {"OpenSSL", wCryptoOpenSSLX25519},
#endif
#if defined(WCRYPTO_HAS_SODIUM_X25519)
    {"libsodium", wCryptoSodiumX25519},
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
    if (! memoryEqual(actual, expected, len))
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

static void require_backend_bytes_equal(const uint8_t *actual, const uint8_t *expected, size_t len, const char *backend,
                                        const char *message)
{
    require_backend(memoryEqual(actual, expected, len), backend, message);
}

static void test_secure_zero(void)
{
    uint8_t bytes[257];
    memorySet(bytes, 0xa5, sizeof(bytes));
    wCryptoZero(bytes, sizeof(bytes));
    for (size_t i = 0; i < sizeof(bytes); ++i)
    {
        require(bytes[i] == 0, "secure zero left nonzero data");
    }

    /* Preserve the established zero-length contract for optional outputs. */
    wCryptoZero(NULL, 0);
}

static void test_secure_equal(void)
{
    uint8_t left[257];
    uint8_t right[257];
    for (size_t i = 0; i < sizeof(left); ++i)
    {
        left[i]  = (uint8_t) i;
        right[i] = (uint8_t) i;
    }

    require(wCryptoEqual(left, right, sizeof(left)), "secure equal rejected identical data");

    right[0] ^= 1;
    require(! wCryptoEqual(left, right, sizeof(left)), "secure equal missed first-byte difference");
    right[0] ^= 1;
    right[sizeof(right) / 2] ^= 1;
    require(! wCryptoEqual(left, right, sizeof(left)), "secure equal missed middle-byte difference");
    right[sizeof(right) / 2] ^= 1;
    right[sizeof(right) - 1] ^= 1;
    require(! wCryptoEqual(left, right, sizeof(left)), "secure equal missed last-byte difference");

    require(wCryptoEqual(NULL, NULL, 0), "secure equal rejected zero-length inputs");
}

static bool bytes_have_value(const uint8_t *bytes, size_t len, uint8_t value)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (bytes[i] != value)
        {
            return false;
        }
    }
    return true;
}

static bool bytes_are_zero(const uint8_t *bytes, size_t len)
{
    return bytes_have_value(bytes, len, 0);
}

static bool aead_backend_is_available(const aead_backend_t *backend)
{
    return backend->is_available == NULL || backend->is_available();
}

static void test_status_strings(void)
{
    const wcrypto_status_t statuses[] = {
        kWCryptoOk,
        kWCryptoInvalidArgument,
        kWCryptoAuthenticationFailed,
        kWCryptoUnavailable,
        kWCryptoInputTooLarge,
        kWCryptoInvalidState,
        kWCryptoRejectedKey,
        kWCryptoBackendFailed,
    };
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
    {
        require(strcmp(wCryptoStatusString(statuses[i]), "unknown crypto status") != 0,
                "defined crypto status has no string");
    }
    require(strcmp(wCryptoStatusString((wcrypto_status_t) -999), "unknown crypto status") == 0,
            "unknown crypto status string mismatch");
}

static void test_global_lifecycle(void)
{
    sha256_hash_t digest;
    memset(&digest, 0xa5, sizeof(digest));
    require(wCryptoSHA256(&digest, NULL, 0) == kWCryptoInvalidState,
            "crypto operation before initialization was accepted");
    require(bytes_are_zero(digest.bytes, sizeof(digest.bytes)), "pre-initialization hash output was not cleared");
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization failed");
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization is not idempotent");
}

static void test_hash_vectors(void)
{
    const uint8_t input[]                       = "abc";
    const uint8_t expected_md5[MD5_DIGEST_SIZE] = {
        0x90,
        0x01,
        0x50,
        0x98,
        0x3c,
        0xd2,
        0x4f,
        0xb0,
        0xd6,
        0x96,
        0x3f,
        0x7d,
        0x28,
        0xe1,
        0x7f,
        0x72,
    };
    const uint8_t expected_sha1[SHA1_DIGEST_SIZE] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    };
    const uint8_t expected_sha224[SHA224_DIGEST_SIZE] = {
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
        0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
    };
    const uint8_t expected_sha256[SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    const uint8_t expected_sha384[SHA384_DIGEST_SIZE] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
    };
    const uint8_t expected_sha512[SHA512_DIGEST_SIZE] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    };
    md5_hash_t    md5    = {0};
    sha1_hash_t   sha1   = {0};
    sha224_hash_t sha224 = {0};
    sha256_hash_t sha256 = {0};
    sha384_hash_t sha384 = {0};
    sha512_hash_t sha512 = {0};

    require(wCryptoMD5(&md5, input, sizeof(input) - 1) == kWCryptoOk, "MD5 failed");
    require_bytes_equal(md5.bytes, expected_md5, sizeof(expected_md5), "MD5 vector mismatch");

    require(wCryptoSHA1(&sha1, input, sizeof(input) - 1) == kWCryptoOk, "SHA1 failed");
    require_bytes_equal(sha1.bytes, expected_sha1, sizeof(expected_sha1), "SHA1 vector mismatch");

    require(wCryptoSHA224(&sha224, input, sizeof(input) - 1) == kWCryptoOk, "SHA224 failed");
    require_bytes_equal(sha224.bytes, expected_sha224, sizeof(expected_sha224), "SHA224 vector mismatch");

    require(wCryptoSHA256(&sha256, input, sizeof(input) - 1) == kWCryptoOk, "SHA256 failed");
    require_bytes_equal(sha256.bytes, expected_sha256, sizeof(expected_sha256), "SHA256 vector mismatch");

    require(wCryptoSHA384(&sha384, input, sizeof(input) - 1) == kWCryptoOk, "SHA384 failed");
    require_bytes_equal(sha384.bytes, expected_sha384, sizeof(expected_sha384), "SHA384 vector mismatch");

    require(wCryptoSHA512(&sha512, input, sizeof(input) - 1) == kWCryptoOk, "SHA512 failed");
    require_bytes_equal(sha512.bytes, expected_sha512, sizeof(expected_sha512), "SHA512 vector mismatch");

#if defined(WCRYPTO_HAS_SOFTWARE_HASH)
    require(wCryptoSoftwareSHA384(&sha384, input, sizeof(input) - 1) == kWCryptoOk, "software SHA384 failed");
    require_bytes_equal(sha384.bytes, expected_sha384, sizeof(expected_sha384), "software SHA384 vector mismatch");
    require(wCryptoSoftwareSHA512(&sha512, input, sizeof(input) - 1) == kWCryptoOk, "software SHA512 failed");
    require_bytes_equal(sha512.bytes, expected_sha512, sizeof(expected_sha512), "software SHA512 vector mismatch");
#endif
}

static void test_hash_contract(void)
{
    const uint8_t expected_empty_sha256[SHA256_DIGEST_SIZE] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    sha256_hash_t   sha256 = {0};
    sha3_256_hash_t sha3;

    require(wCryptoSHA256(&sha256, NULL, 0) == kWCryptoOk, "empty SHA256 failed");
    require_bytes_equal(
        sha256.bytes, expected_empty_sha256, sizeof(expected_empty_sha256), "empty SHA256 vector mismatch");
    require(wCryptoSHA256(NULL, NULL, 0) == kWCryptoInvalidArgument, "NULL hash output was accepted");
    memset(&sha256, 0xa5, sizeof(sha256));
    require(wCryptoSHA256(&sha256, NULL, 1) == kWCryptoInvalidArgument, "NULL non-empty hash input was accepted");
    require(bytes_are_zero(sha256.bytes, sizeof(sha256.bytes)), "invalid hash input did not clear output");
#if SIZE_MAX > UINT32_MAX
    memset(&sha256, 0xa5, sizeof(sha256));
    require(wCryptoSHA256(&sha256, (const uint8_t *) (uintptr_t) 1, (size_t) UINT32_MAX + 1) == kWCryptoInputTooLarge,
            "oversized hash input was not rejected before dereference");
    require(bytes_are_zero(sha256.bytes, sizeof(sha256.bytes)), "oversized hash input did not clear output");
#endif

    memset(&sha3, 0xa5, sizeof(sha3));
#if defined(WCRYPTO_HAS_OPENSSL_HASH)
    require(wCryptoSHA3_256(&sha3, NULL, 0) == kWCryptoOk, "OpenSSL SHA3-256 reported unavailable");
#else
    require(wCryptoSHA3_256(&sha3, NULL, 0) == kWCryptoUnavailable, "unavailable SHA3-256 returned the wrong status");
    require(bytes_are_zero(sha3.bytes, sizeof(sha3.bytes)), "unavailable SHA3-256 output was not cleared");
#endif
}

static void test_blake2s_unkeyed(void)
{
    const uint8_t input[]                       = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    const uint8_t expected[BLAKE2S_DIGEST_SIZE] = {
        0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
        0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
    };
    uint8_t output[BLAKE2S_DIGEST_SIZE] = {0};

    require(wCryptoBlake2s(output, sizeof(output), NULL, 0, input, sizeof(input) - 1) == kWCryptoOk, "BLAKE2s failed");
    require_bytes_equal(output, expected, sizeof(output), "BLAKE2s unkeyed vector mismatch");
}

static void test_blake2s_keyed(void)
{
    const uint8_t input[]                       = "Salam farmande! seyed ali dahe 80 hasho fara khande!";
    const uint8_t key[]                         = {0x00, 0x01, 0x02, 0x03};
    const uint8_t expected[BLAKE2S_DIGEST_SIZE] = {
        0xf5, 0xae, 0x22, 0xd5, 0xd5, 0x5f, 0xb3, 0x1e, 0x5c, 0xf2, 0x61, 0x99, 0x9c, 0x2f, 0x5d, 0x88,
        0x95, 0xb3, 0xf2, 0x02, 0x32, 0x57, 0x19, 0x61, 0x43, 0x9e, 0xcf, 0x58, 0x6e, 0x58, 0x48, 0xed,
    };
    uint8_t output[BLAKE2S_DIGEST_SIZE] = {0};

    require(wCryptoBlake2s(output, sizeof(output), key, sizeof(key), input, sizeof(input) - 1) == kWCryptoOk,
            "Keyed BLAKE2s failed");
    require_bytes_equal(output, expected, sizeof(output), "BLAKE2s keyed vector mismatch");
}

static void test_blake2s_lifecycle(void)
{
    const uint8_t         first[]  = "incremental ";
    const uint8_t         second[] = "BLAKE2s";
    uint8_t               combined[sizeof(first) - 1 + sizeof(second) - 1];
    uint8_t               expected[16] = {0};
    uint8_t               actual[16]   = {0};
    wcrypto_blake2s_ctx_t ctx          = WCRYPTO_BLAKE2S_CONTEXT_INITIALIZER;

    memcpy(combined, first, sizeof(first) - 1);
    memcpy(combined + sizeof(first) - 1, second, sizeof(second) - 1);
    require(wCryptoBlake2s(expected, sizeof(expected), NULL, 0, combined, sizeof(combined)) == kWCryptoOk,
            "truncated one-shot BLAKE2s failed");
    require(wCryptoBlake2sInit(&ctx, sizeof(actual), NULL, 0) == kWCryptoOk, "BLAKE2s context initialization failed");
    require(wCryptoBlake2sInit(&ctx, sizeof(actual), NULL, 0) == kWCryptoInvalidState,
            "active BLAKE2s context was reinitialized");
    require(wCryptoBlake2sUpdate(&ctx, NULL, 0) == kWCryptoOk, "zero-length BLAKE2s update failed");
    require(wCryptoBlake2sUpdate(&ctx, first, sizeof(first) - 1) == kWCryptoOk, "first BLAKE2s update failed");
    require(wCryptoBlake2sUpdate(&ctx, second, sizeof(second) - 1) == kWCryptoOk, "second BLAKE2s update failed");
    require(wCryptoBlake2sFinal(&ctx, actual, sizeof(actual)) == kWCryptoOk, "BLAKE2s finalization failed");
    require_bytes_equal(actual, expected, sizeof(actual), "incremental BLAKE2s differs from one-shot");
    require(wCryptoBlake2sUpdate(&ctx, first, sizeof(first) - 1) == kWCryptoInvalidState,
            "finalized BLAKE2s context accepted an update");
    memset(actual, 0xa5, sizeof(actual));
    require(wCryptoBlake2sFinal(&ctx, actual, sizeof(actual)) == kWCryptoInvalidState,
            "BLAKE2s context was finalized twice");
    require(bytes_are_zero(actual, sizeof(actual)), "second BLAKE2s final did not clear output");

    require(wCryptoBlake2sInit(&ctx, sizeof(actual), NULL, 0) == kWCryptoOk,
            "BLAKE2s context was not reusable after finalization");
    memset(actual, 0xa5, sizeof(actual));
    require(wCryptoBlake2sFinal(&ctx, actual, sizeof(actual) - 1) == kWCryptoInvalidArgument,
            "BLAKE2s accepted a mismatched final output length");
    require(bytes_are_zero(actual, sizeof(actual) - 1) && actual[sizeof(actual) - 1] == 0xa5,
            "mismatched BLAKE2s final did not clear exactly the validated output region");
    require(wCryptoBlake2sUpdate(&ctx, first, sizeof(first) - 1) == kWCryptoInvalidState,
            "failed BLAKE2s final left the context active");

    require(wCryptoBlake2sInit(&ctx, sizeof(actual), NULL, 0) == kWCryptoOk,
            "BLAKE2s context was not reusable after failed finalization");
    wCryptoBlake2sDestroy(&ctx);
    wCryptoBlake2sDestroy(&ctx);
    require(wCryptoBlake2sInit(&ctx, sizeof(actual), NULL, 0) == kWCryptoOk,
            "BLAKE2s context was not reusable after destruction");
    wCryptoBlake2sDestroy(&ctx);
    wCryptoBlake2sDestroy(&ctx);

    require(wCryptoBlake2sInit(&ctx, 0, NULL, 0) == kWCryptoInvalidArgument, "zero BLAKE2s digest length was accepted");
    require(wCryptoBlake2sInit(&ctx, WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE + 1, NULL, 0) == kWCryptoInvalidArgument,
            "oversized BLAKE2s digest was accepted");
    require(wCryptoBlake2sInit(&ctx, sizeof(actual), NULL, 1) == kWCryptoInvalidArgument,
            "NULL non-empty BLAKE2s key was accepted");
    require(wCryptoBlake2sUpdate(&ctx, first, sizeof(first) - 1) == kWCryptoInvalidState,
            "zero BLAKE2s context accepted an update");
    memset(actual, 0xa5, sizeof(actual));
    require(wCryptoBlake2sFinal(&ctx, actual, sizeof(actual)) == kWCryptoInvalidState,
            "zero BLAKE2s context accepted finalization");
    require(bytes_are_zero(actual, sizeof(actual)), "invalid-state BLAKE2s final did not clear output");
    memset(actual, 0xa5, sizeof(actual));
    require(wCryptoBlake2sFinal(NULL, actual, sizeof(actual)) == kWCryptoInvalidArgument,
            "NULL BLAKE2s context was accepted for finalization");
    require(bytes_are_zero(actual, sizeof(actual)), "NULL-context BLAKE2s final did not clear output");
    memset(actual, 0xa5, sizeof(actual));
    require(wCryptoBlake2s(actual, sizeof(actual), NULL, 0, NULL, 1) == kWCryptoInvalidArgument,
            "NULL non-empty BLAKE2s input was accepted");
    require(bytes_are_zero(actual, sizeof(actual)), "invalid BLAKE2s input did not clear output");
}

#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
static wcrypto_status_t software_blake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen,
                                         const unsigned char *in, size_t inlen)
{
    wcrypto_software_blake2s_ctx_t ctx    = {0};
    wcrypto_status_t               status = wCryptoSoftwareBlake2sInit(&ctx, outlen, key, keylen);
    if (status == kWCryptoOk)
    {
        status = wCryptoSoftwareBlake2sUpdate(&ctx, in, inlen);
    }
    if (status == kWCryptoOk)
    {
        status = wCryptoSoftwareBlake2sFinal(&ctx, out, outlen);
    }
    else
    {
        wCryptoSoftwareBlake2sDestroy(&ctx);
    }
    return status;
}
#endif

static void test_blake2s_lengths_and_reuse(void)
{
    const uint8_t input[] = "BLAKE2s backend-independent length contract";
    uint8_t       key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE];
    uint8_t       expected[WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE];
    uint8_t       actual[WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE];
    const size_t  key_lengths[] = {0, 1, WCRYPTO_BLAKE2S_MAX_KEY_SIZE};

#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
    require(! wCryptoOpenSSLBlake2sIsAvailable(16, 0),
            "OpenSSL BLAKE2s incorrectly advertised truncated unkeyed support");
#endif

    for (size_t i = 0; i < sizeof(key); ++i)
    {
        key[i] = (uint8_t) i;
    }

    for (size_t digest_len = 1; digest_len <= WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE; ++digest_len)
    {
        for (size_t key_index = 0; key_index < sizeof(key_lengths) / sizeof(key_lengths[0]); ++key_index)
        {
            const size_t          key_len = key_lengths[key_index];
            const uint8_t        *key_ptr = key_len == 0 ? NULL : key;
            wcrypto_blake2s_ctx_t ctx     = WCRYPTO_BLAKE2S_CONTEXT_INITIALIZER;

            memset(expected, 0, sizeof(expected));
            memset(actual, 0, sizeof(actual));
            require(wCryptoBlake2s(expected, digest_len, key_ptr, key_len, input, sizeof(input) - 1) == kWCryptoOk,
                    "BLAKE2s one-shot length/key combination failed");
            require(wCryptoBlake2sInit(&ctx, digest_len, key_ptr, key_len) == kWCryptoOk,
                    "BLAKE2s streaming length/key combination failed to initialize");
            require(wCryptoBlake2sUpdate(&ctx, input, 7) == kWCryptoOk &&
                        wCryptoBlake2sUpdate(&ctx, NULL, 0) == kWCryptoOk &&
                        wCryptoBlake2sUpdate(&ctx, input + 7, sizeof(input) - 1 - 7) == kWCryptoOk,
                    "BLAKE2s streaming update failed");
            require(wCryptoBlake2sFinal(&ctx, actual, digest_len) == kWCryptoOk, "BLAKE2s streaming final failed");
            require_bytes_equal(actual, expected, digest_len, "BLAKE2s one-shot/streaming mismatch");

#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
            memset(actual, 0, sizeof(actual));
            require(software_blake2s(actual, digest_len, key_ptr, key_len, input, sizeof(input) - 1) == kWCryptoOk,
                    "software BLAKE2s length/key combination failed");
            require_bytes_equal(actual, expected, digest_len, "public/software BLAKE2s mismatch");
#endif
        }
    }

    memset(actual, 0xa5, sizeof(actual));
    require(wCryptoBlake2s(actual, sizeof(actual), key, sizeof(key) + 1, input, sizeof(input) - 1) ==
                kWCryptoInvalidArgument,
            "oversized BLAKE2s key was accepted");
    require(bytes_are_zero(actual, sizeof(actual)), "invalid-key BLAKE2s output was not cleared");
    require(wCryptoBlake2s(NULL, sizeof(actual), NULL, 0, input, sizeof(input) - 1) == kWCryptoInvalidArgument,
            "NULL BLAKE2s output was accepted");

    for (size_t iteration = 0; iteration < 256; ++iteration)
    {
        wcrypto_blake2s_ctx_t ctx = WCRYPTO_BLAKE2S_CONTEXT_INITIALIZER;
        require(wCryptoBlake2sInit(&ctx, 16, key, 1) == kWCryptoOk &&
                    wCryptoBlake2sUpdate(&ctx, input, sizeof(input) - 1) == kWCryptoOk &&
                    wCryptoBlake2sFinal(&ctx, actual, 16) == kWCryptoOk,
                "repeated BLAKE2s lifecycle failed");
        wCryptoBlake2sDestroy(&ctx);
    }
}

static void test_x25519(void)
{
    const uint8_t scalar[X25519_KEY_SIZE] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const uint8_t point[X25519_KEY_SIZE] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    };
    const uint8_t expected[X25519_KEY_SIZE] = {
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    };
    uint8_t shared_secret[X25519_KEY_SIZE] = {0};
    uint8_t high_bit_point[X25519_KEY_SIZE];
    memcpy(high_bit_point, point, sizeof(high_bit_point));
    high_bit_point[sizeof(high_bit_point) - 1] |= UINT8_C(0x80);

    for (size_t i = 0; i < sizeof(x25519_backends) / sizeof(x25519_backends[0]); ++i)
    {
        memset(shared_secret, 0, sizeof(shared_secret));
        require_backend(x25519_backends[i].derive(shared_secret, scalar, point) == kWCryptoOk,
                        x25519_backends[i].name,
                        "X25519 failed");
        require_backend_bytes_equal(
            shared_secret, expected, sizeof(shared_secret), x25519_backends[i].name, "X25519 vector mismatch");

        memset(shared_secret, 0, sizeof(shared_secret));
        require_backend(x25519_backends[i].derive(shared_secret, scalar, high_bit_point) == kWCryptoOk,
                        x25519_backends[i].name,
                        "X25519 rejected an RFC 7748 high-bit encoding");
        require_backend_bytes_equal(shared_secret,
                                    expected,
                                    sizeof(shared_secret),
                                    x25519_backends[i].name,
                                    "X25519 did not ignore the input point high bit");

        memset(shared_secret, 0xa5, sizeof(shared_secret));
        require_backend(x25519_backends[i].derive(shared_secret, NULL, point) == kWCryptoInvalidArgument,
                        x25519_backends[i].name,
                        "NULL X25519 scalar was accepted");
        require_backend(bytes_are_zero(shared_secret, sizeof(shared_secret)),
                        x25519_backends[i].name,
                        "invalid X25519 scalar did not clear output");
    }

    require(wCryptoX25519(NULL, scalar, point) == kWCryptoInvalidArgument, "NULL X25519 output was accepted");
    memset(shared_secret, 0xa5, sizeof(shared_secret));
    require(wCryptoX25519(shared_secret, scalar, NULL) == kWCryptoInvalidArgument, "NULL X25519 point was accepted");
    require(bytes_are_zero(shared_secret, sizeof(shared_secret)), "invalid X25519 point did not clear output");

#if defined(WCRYPTO_HAS_SOFTWARE_X25519)
    union {
        uint32_t alignment;
        uint8_t  bytes[X25519_KEY_SIZE + 1];
    } point_storage          = {0};
    uint8_t *unaligned_point = point_storage.bytes + 1;

    memcpy(unaligned_point, point, sizeof(point));
    require(wCryptoSoftwareX25519(shared_secret, scalar, unaligned_point) == kWCryptoOk,
            "Software X25519 failed with an unaligned public key");
    require_bytes_equal(
        shared_secret, expected, sizeof(shared_secret), "Software X25519 unaligned public key mismatch");
#endif
}

static void test_x25519_rejected_key(void)
{
    const uint8_t scalar[WCRYPTO_X25519_KEY_SIZE]          = {1};
    const uint8_t low_order_point[WCRYPTO_X25519_KEY_SIZE] = {0};
    uint8_t       output[WCRYPTO_X25519_KEY_SIZE];

    for (size_t i = 0; i < sizeof(x25519_backends) / sizeof(x25519_backends[0]); ++i)
    {
        memset(output, 0xa5, sizeof(output));
        require_backend(x25519_backends[i].derive(output, scalar, low_order_point) == kWCryptoRejectedKey,
                        x25519_backends[i].name,
                        "low-order X25519 point was accepted");
        require_backend(
            bytes_are_zero(output, sizeof(output)), x25519_backends[i].name, "rejected X25519 output was not cleared");
    }
}

static void test_chacha20poly1305(void)
{
    const char    plaintext[]                                           = "This is a secret message!";
    const char    ad[]                                                  = "Additional authenticated data";
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE]                        = {0x00};
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE]                    = {0, 0, 0, 0, 88, 90, 07, 1, 2, 3, 4, 8};
    const uint8_t expected[(sizeof(plaintext) - 1) + POLY1305_TAG_SIZE] = {
        0x88, 0x10, 0xcc, 0x6b, 0xc6, 0x12, 0xb2, 0xe3, 0x71, 0xf9, 0x9a, 0x1e, 0xed, 0x2b,
        0x87, 0x27, 0x50, 0x1d, 0x2a, 0xba, 0xf0, 0x77, 0x03, 0xb6, 0x63, 0x16, 0x50, 0xd2,
        0x52, 0x5b, 0x16, 0xb7, 0x18, 0xd8, 0x8e, 0x24, 0x51, 0x67, 0x41, 0xb7, 0x1e,
    };
    uint8_t ciphertext[sizeof(expected)]     = {0};
    uint8_t decrypted[sizeof(plaintext) - 1] = {0};

    require(wCryptoChaCha20Poly1305Encrypt(ciphertext,
                                           sizeof(ciphertext),
                                           (const uint8_t *) plaintext,
                                           sizeof(plaintext) - 1,
                                           (const uint8_t *) ad,
                                           sizeof(ad) - 1,
                                           nonce,
                                           key) == kWCryptoOk,
            "ChaCha20-Poly1305 encryption failed");
    require_bytes_equal(ciphertext, expected, sizeof(ciphertext), "ChaCha20-Poly1305 vector mismatch");

    require(wCryptoChaCha20Poly1305Decrypt(decrypted,
                                           sizeof(decrypted),
                                           ciphertext,
                                           sizeof(ciphertext),
                                           (const uint8_t *) ad,
                                           sizeof(ad) - 1,
                                           nonce,
                                           key) == kWCryptoOk,
            "ChaCha20-Poly1305 decryption failed");
    require_bytes_equal(
        decrypted, (const uint8_t *) plaintext, sizeof(decrypted), "ChaCha20-Poly1305 round trip failed");
}

static void test_chacha20poly1305_nonzero_prefix_and_interoperability(void)
{
    const uint8_t plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65,
        0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20,
        0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c,
        0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20,
        0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66,
        0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20,
        0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    };
    const uint8_t ad[] = {
        0x50,
        0x51,
        0x52,
        0x53,
        0xc0,
        0xc1,
        0xc2,
        0xc3,
        0xc4,
        0xc5,
        0xc6,
        0xc7,
    };
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE] = {
        0x07,
        0x00,
        0x00,
        0x00,
        0x40,
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46,
        0x47,
    };
    const uint8_t expected[sizeof(plaintext) + POLY1305_TAG_SIZE] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4,
        0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe,
        0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde,
        0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f,
        0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa,
        0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b,
        0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f,
        0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };
    uint8_t      outputs[sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0])][sizeof(expected)];
    uint8_t      decrypted[sizeof(plaintext)];
    const size_t backend_count = sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]);

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        const aead_backend_t *backend = &chacha20poly1305_backends[producer];
        require_backend(backend->encrypt(outputs[producer],
                                         sizeof(outputs[producer]),
                                         plaintext,
                                         sizeof(plaintext),
                                         ad,
                                         sizeof(ad),
                                         nonce,
                                         key) == kWCryptoOk,
                        backend->name,
                        "RFC 8439 encryption failed");
        require_backend_bytes_equal(
            outputs[producer], expected, sizeof(expected), backend->name, "RFC 8439 ciphertext/tag mismatch");
    }

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        for (size_t consumer = 0; consumer < backend_count; ++consumer)
        {
            const aead_backend_t *backend = &chacha20poly1305_backends[consumer];
            memoryZero(decrypted, sizeof(decrypted));
            require_backend(
                backend->decrypt(
                    decrypted, sizeof(decrypted), outputs[producer], sizeof(expected), ad, sizeof(ad), nonce, key) ==
                    kWCryptoOk,
                backend->name,
                "cross-backend RFC 8439 decryption failed");
            require_backend_bytes_equal(
                decrypted, plaintext, sizeof(plaintext), backend->name, "cross-backend RFC 8439 plaintext mismatch");
        }
    }
}

static void test_chacha20poly1305_nonce_prefix_sensitivity(void)
{
    const uint8_t plaintext[]                          = "nonce-prefix-sensitivity";
    const uint8_t ad[]                                 = "nonce-prefix-aad";
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE]       = {0x42};
    const uint8_t nonce_a[CHACHA20POLY1305_NONCE_SIZE] = {
        0x01,
        0x02,
        0x03,
        0x04,
        0x40,
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46,
        0x47,
    };
    const uint8_t nonce_b[CHACHA20POLY1305_NONCE_SIZE] = {
        0x05,
        0x06,
        0x07,
        0x08,
        0x40,
        0x41,
        0x42,
        0x43,
        0x44,
        0x45,
        0x46,
        0x47,
    };
    uint8_t      ciphertext_a[sizeof(plaintext) - 1 + POLY1305_TAG_SIZE];
    uint8_t      ciphertext_b[sizeof(ciphertext_a)];
    uint8_t      decrypted[sizeof(plaintext) - 1];
    const size_t backend_count = sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]);

    for (size_t i = 0; i < backend_count; ++i)
    {
        const aead_backend_t *backend = &chacha20poly1305_backends[i];
        require_backend(backend->encrypt(ciphertext_a,
                                         sizeof(ciphertext_a),
                                         plaintext,
                                         sizeof(plaintext) - 1,
                                         ad,
                                         sizeof(ad) - 1,
                                         nonce_a,
                                         key) == kWCryptoOk,
                        backend->name,
                        "nonce A encryption failed");
        require_backend(backend->encrypt(ciphertext_b,
                                         sizeof(ciphertext_b),
                                         plaintext,
                                         sizeof(plaintext) - 1,
                                         ad,
                                         sizeof(ad) - 1,
                                         nonce_b,
                                         key) == kWCryptoOk,
                        backend->name,
                        "nonce B encryption failed");
        require_backend(! memoryEqual(ciphertext_a, ciphertext_b, sizeof(ciphertext_a)),
                        backend->name,
                        "changing nonce bytes 0-3 did not change ciphertext/tag");

        require_backend(
            backend->decrypt(
                decrypted, sizeof(decrypted), ciphertext_a, sizeof(ciphertext_a), ad, sizeof(ad) - 1, nonce_a, key) ==
                kWCryptoOk,
            backend->name,
            "matching nonce A decryption failed");
        require_backend_bytes_equal(
            decrypted, plaintext, sizeof(decrypted), backend->name, "matching nonce A plaintext mismatch");
        require_backend(
            backend->decrypt(
                decrypted, sizeof(decrypted), ciphertext_b, sizeof(ciphertext_b), ad, sizeof(ad) - 1, nonce_b, key) ==
                kWCryptoOk,
            backend->name,
            "matching nonce B decryption failed");
        require_backend_bytes_equal(
            decrypted, plaintext, sizeof(decrypted), backend->name, "matching nonce B plaintext mismatch");
        require_backend(
            backend->decrypt(
                decrypted, sizeof(decrypted), ciphertext_a, sizeof(ciphertext_a), ad, sizeof(ad) - 1, nonce_b, key) ==
                kWCryptoAuthenticationFailed,
            backend->name,
            "wrong nonce prefix authenticated");
        require_backend(
            backend->decrypt(
                decrypted, sizeof(decrypted), ciphertext_b, sizeof(ciphertext_b), ad, sizeof(ad) - 1, nonce_a, key) ==
                kWCryptoAuthenticationFailed,
            backend->name,
            "reverse wrong nonce prefix authenticated");
    }
}

static void test_aead_short_ciphertexts(const aead_backend_t *backends, size_t backend_count, const uint8_t *nonce)
{
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE] = {0};
    uint8_t       ciphertext[POLY1305_TAG_SIZE]  = {0};
    uint8_t       decrypted                      = 0;

    for (size_t backend_index = 0; backend_index < backend_count; ++backend_index)
    {
        const aead_backend_t *backend = &backends[backend_index];
        if (! aead_backend_is_available(backend))
        {
            continue;
        }

        for (size_t ciphertext_len = 0; ciphertext_len < POLY1305_TAG_SIZE; ++ciphertext_len)
        {
            require_backend(
                backend->decrypt(&decrypted, sizeof(decrypted), ciphertext, ciphertext_len, NULL, 0, nonce, key) ==
                    kWCryptoInvalidArgument,
                backend->name,
                "short AEAD ciphertext was accepted");
        }

        require_backend(backend->encrypt(ciphertext, sizeof(ciphertext), NULL, 0, NULL, 0, nonce, key) == kWCryptoOk,
                        backend->name,
                        "empty AEAD plaintext encryption failed");
        require_backend(backend->decrypt(NULL, 0, ciphertext, sizeof(ciphertext), NULL, 0, nonce, key) == kWCryptoOk,
                        backend->name,
                        "tag-only AEAD ciphertext was rejected");
        require_backend(backend->decrypt(NULL, 1, ciphertext, sizeof(ciphertext), NULL, 0, nonce, key) ==
                            kWCryptoInvalidArgument,
                        backend->name,
                        "NULL tag-only destination accepted nonzero capacity");
    }
}

static void test_aead_boundary_lengths(const aead_backend_t *backends, size_t backend_count, const uint8_t *nonce)
{
    static const size_t lengths[] = {
        0,
        1,
        POLY1305_TAG_SIZE - 1,
        POLY1305_TAG_SIZE,
        POLY1305_TAG_SIZE + 1,
        31,
        32,
        33,
        ENCRYPTION_RUNTIME_MAX_FRAME_PAYLOAD - 1,
        ENCRYPTION_RUNTIME_MAX_FRAME_PAYLOAD,
        ENCRYPTION_RUNTIME_MAX_FRAME_PAYLOAD + 1,
    };
    const size_t  max_plaintext_len                      = lengths[sizeof(lengths) / sizeof(lengths[0]) - 1];
    const uint8_t ad[]                                   = "AEAD boundary metadata";
    const uint8_t key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE] = {0x6d};
    uint8_t      *plaintext                              = malloc(max_plaintext_len);
    uint8_t      *ciphertext                             = malloc(max_plaintext_len + WCRYPTO_AEAD_TAG_SIZE);
    uint8_t      *decrypted                              = malloc(max_plaintext_len);

    require(plaintext != NULL && ciphertext != NULL && decrypted != NULL, "failed to allocate AEAD boundary buffers");
    for (size_t i = 0; i < max_plaintext_len; ++i)
    {
        plaintext[i] = (uint8_t) (i * 37U + 11U);
    }

    for (size_t backend_index = 0; backend_index < backend_count; ++backend_index)
    {
        const aead_backend_t *backend = &backends[backend_index];
        if (! aead_backend_is_available(backend))
        {
            continue;
        }

        for (size_t length_index = 0; length_index < sizeof(lengths) / sizeof(lengths[0]); ++length_index)
        {
            const size_t   plaintext_len  = lengths[length_index];
            const size_t   ciphertext_len = plaintext_len + WCRYPTO_AEAD_TAG_SIZE;
            const uint8_t *source         = plaintext_len == 0 ? NULL : plaintext;
            uint8_t       *destination    = plaintext_len == 0 ? NULL : decrypted;

            memset(ciphertext, 0xa5, ciphertext_len);
            memset(decrypted, 0xa5, max_plaintext_len);
            require_backend(
                backend->encrypt(ciphertext, ciphertext_len, source, plaintext_len, ad, sizeof(ad) - 1, nonce, key) ==
                    kWCryptoOk,
                backend->name,
                "AEAD boundary encryption failed");
            require_backend(
                backend->decrypt(
                    destination, plaintext_len, ciphertext, ciphertext_len, ad, sizeof(ad) - 1, nonce, key) ==
                    kWCryptoOk,
                backend->name,
                "AEAD boundary decryption failed");
            if (plaintext_len != 0)
            {
                require_backend_bytes_equal(
                    decrypted, plaintext, plaintext_len, backend->name, "AEAD boundary plaintext mismatch");
            }
        }
    }

    memset(plaintext, 0, max_plaintext_len);
    memset(ciphertext, 0, max_plaintext_len + WCRYPTO_AEAD_TAG_SIZE);
    memset(decrypted, 0, max_plaintext_len);
    free(plaintext);
    free(ciphertext);
    free(decrypted);
}

static void test_aead_contract(const aead_backend_t *backends, size_t backend_count, const uint8_t *nonce,
                               size_t nonce_len)
{
    const uint8_t plaintext[]                                       = "AEAD contract boundary payload";
    const uint8_t ad[]                                              = "authenticated metadata";
    uint8_t       key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]            = {0x42};
    uint8_t       wrong_key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]      = {0x43};
    uint8_t       wrong_nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE] = {0};
    uint8_t       ciphertext[sizeof(plaintext) - 1 + WCRYPTO_AEAD_TAG_SIZE];
    uint8_t       work[sizeof(ciphertext)];
    uint8_t       output[sizeof(plaintext) - 1];

    memcpy(wrong_nonce, nonce, nonce_len);
    wrong_nonce[nonce_len - 1] ^= 1;
    for (size_t i = 0; i < backend_count; ++i)
    {
        const aead_backend_t *backend = &backends[i];
        if (! aead_backend_is_available(backend))
        {
            continue;
        }
        require_backend(
            backend->encrypt(
                ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoOk,
            backend->name,
            "contract encryption failed");
        memset(ciphertext, 0xa5, sizeof(ciphertext));
        require_backend(
            backend->encrypt(
                ciphertext, sizeof(ciphertext) - 1, plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoInvalidArgument,
            backend->name,
            "insufficient encryption capacity was accepted");
        require_backend(bytes_have_value(ciphertext, sizeof(ciphertext), 0xa5),
                        backend->name,
                        "insufficient encryption capacity caused an output write");
        memset(output, 0xa5, sizeof(output));
        require_backend(
            backend->decrypt(
                output, sizeof(output) - 1, ciphertext, sizeof(ciphertext), ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoInvalidArgument,
            backend->name,
            "insufficient decryption capacity was accepted");
        require_backend(bytes_have_value(output, sizeof(output), 0xa5),
                        backend->name,
                        "insufficient decryption capacity caused an output write");
        memset(ciphertext, 0xa5, sizeof(ciphertext));
        require_backend(
            backend->encrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext) - 1, NULL, 1, nonce, key) ==
                kWCryptoInvalidArgument,
            backend->name,
            "NULL non-empty AAD was accepted");
        require_backend(bytes_are_zero(ciphertext, sizeof(ciphertext)),
                        backend->name,
                        "invalid encryption AAD did not clear output");
        memset(ciphertext, 0xa5, sizeof(ciphertext));
        require_backend(
            backend->encrypt(
                ciphertext, sizeof(ciphertext), NULL, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoInvalidArgument,
            backend->name,
            "NULL non-empty plaintext was accepted");
        require_backend(bytes_are_zero(ciphertext, sizeof(ciphertext)),
                        backend->name,
                        "invalid encryption input did not clear output");
        require_backend(
            backend->encrypt(
                NULL, sizeof(ciphertext), plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoInvalidArgument,
            backend->name,
            "NULL encryption destination was accepted");
        memset(ciphertext, 0xa5, sizeof(ciphertext));
        require_backend(
            backend->encrypt(
                ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, NULL, key) ==
                kWCryptoInvalidArgument,
            backend->name,
            "NULL nonce was accepted");
        require_backend(bytes_are_zero(ciphertext, sizeof(ciphertext)),
                        backend->name,
                        "invalid encryption nonce did not clear output");
        memset(ciphertext, 0xa5, sizeof(ciphertext));
        require_backend(
            backend->encrypt(
                ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, nonce, NULL) ==
                kWCryptoInvalidArgument,
            backend->name,
            "NULL key was accepted");
        require_backend(bytes_are_zero(ciphertext, sizeof(ciphertext)),
                        backend->name,
                        "invalid encryption key did not clear output");
        memset(ciphertext, 0xa5, sizeof(ciphertext));
        require_backend(backend->encrypt(ciphertext,
                                         sizeof(ciphertext),
                                         (const uint8_t *) (uintptr_t) 1,
                                         WCRYPTO_AEAD_MAX_INPUT_SIZE - WCRYPTO_AEAD_TAG_SIZE + 1,
                                         NULL,
                                         0,
                                         nonce,
                                         key) == kWCryptoInputTooLarge,
                        backend->name,
                        "oversized encryption input was not rejected first");
        require_backend(bytes_have_value(ciphertext, sizeof(ciphertext), 0xa5),
                        backend->name,
                        "oversized encryption input caused an output write");
        memset(output, 0xa5, sizeof(output));
        require_backend(backend->decrypt(output,
                                         sizeof(output),
                                         (const uint8_t *) (uintptr_t) 1,
                                         WCRYPTO_AEAD_MAX_INPUT_SIZE + 1,
                                         NULL,
                                         0,
                                         nonce,
                                         key) == kWCryptoInputTooLarge,
                        backend->name,
                        "oversized decryption input was not rejected first");
        require_backend(bytes_have_value(output, sizeof(output), 0xa5),
                        backend->name,
                        "oversized decryption input caused an output write");

        memset(ciphertext, 0xa5, sizeof(ciphertext));
        require_backend(backend->encrypt(ciphertext,
                                         sizeof(ciphertext),
                                         plaintext,
                                         sizeof(plaintext) - 1,
                                         (const uint8_t *) (uintptr_t) 1,
                                         WCRYPTO_AEAD_MAX_INPUT_SIZE + 1,
                                         nonce,
                                         key) == kWCryptoInputTooLarge,
                        backend->name,
                        "oversized AAD was not rejected first");
        require_backend(bytes_have_value(ciphertext, sizeof(ciphertext), 0xa5),
                        backend->name,
                        "oversized AAD caused an output write");

        memset(output, 0xa5, sizeof(output));
        require_backend(
            backend->decrypt(output, sizeof(output), NULL, sizeof(ciphertext), ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoInvalidArgument,
            backend->name,
            "NULL non-empty ciphertext was accepted");
        require_backend(
            bytes_are_zero(output, sizeof(output)), backend->name, "invalid decryption input did not clear output");

        memcpy(work, plaintext, sizeof(plaintext) - 1);
        require_backend(
            backend->encrypt(work, sizeof(work), work, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoOk,
            backend->name,
            "in-place encryption failed");
        require_backend(backend->decrypt(work, sizeof(work), work, sizeof(work), ad, sizeof(ad) - 1, nonce, key) ==
                            kWCryptoOk,
                        backend->name,
                        "in-place decryption failed");
        require_backend_bytes_equal(
            work, plaintext, sizeof(plaintext) - 1, backend->name, "in-place AEAD round trip mismatch");

        require_backend(
            backend->encrypt(
                ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext) - 1, ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoOk,
            backend->name,
            "authentication-failure setup failed");
        ciphertext[sizeof(ciphertext) - 1] ^= 1;
        memset(output, 0xa5, sizeof(output));
        require_backend(
            backend->decrypt(output, sizeof(output), ciphertext, sizeof(ciphertext), ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoAuthenticationFailed,
            backend->name,
            "tampered tag authenticated");
        require_backend(
            bytes_are_zero(output, sizeof(output)), backend->name, "unauthenticated plaintext was not cleared");
        ciphertext[sizeof(ciphertext) - 1] ^= 1;

        memset(output, 0xa5, sizeof(output));
        require_backend(
            backend->decrypt(
                output, sizeof(output), ciphertext, sizeof(ciphertext), ad, sizeof(ad) - 1, nonce, wrong_key) ==
                kWCryptoAuthenticationFailed,
            backend->name,
            "wrong key authenticated");
        require_backend(bytes_are_zero(output, sizeof(output)), backend->name, "wrong-key plaintext was not cleared");
        memset(output, 0xa5, sizeof(output));
        require_backend(
            backend->decrypt(
                output, sizeof(output), ciphertext, sizeof(ciphertext), ad, sizeof(ad) - 1, wrong_nonce, key) ==
                kWCryptoAuthenticationFailed,
            backend->name,
            "wrong nonce authenticated");
        require_backend(bytes_are_zero(output, sizeof(output)), backend->name, "wrong-nonce plaintext was not cleared");

        uint8_t wrong_ad[sizeof(ad) - 1];
        memcpy(wrong_ad, ad, sizeof(wrong_ad));
        wrong_ad[0] ^= 1;
        memset(output, 0xa5, sizeof(output));
        require_backend(
            backend->decrypt(
                output, sizeof(output), ciphertext, sizeof(ciphertext), wrong_ad, sizeof(wrong_ad), nonce, key) ==
                kWCryptoAuthenticationFailed,
            backend->name,
            "wrong AAD authenticated");
        require_backend(bytes_are_zero(output, sizeof(output)), backend->name, "wrong-AAD plaintext was not cleared");

        ciphertext[0] ^= 1;
        memset(output, 0xa5, sizeof(output));
        require_backend(
            backend->decrypt(output, sizeof(output), ciphertext, sizeof(ciphertext), ad, sizeof(ad) - 1, nonce, key) ==
                kWCryptoAuthenticationFailed,
            backend->name,
            "tampered ciphertext authenticated");
        require_backend(
            bytes_are_zero(output, sizeof(output)), backend->name, "tampered-ciphertext plaintext was not cleared");
        ciphertext[0] ^= 1;
    }
}

static void test_unavailable_software_aes(void)
{
    uint8_t       output[WCRYPTO_AEAD_TAG_SIZE];
    const uint8_t nonce[WCRYPTO_AES256GCM_NONCE_SIZE] = {0};
    const uint8_t key[WCRYPTO_AES256GCM_KEY_SIZE]     = {0};
    memset(output, 0xa5, sizeof(output));
    require(wCryptoSoftwareAES256GCMEncrypt(output, sizeof(output), NULL, 0, NULL, 0, nonce, key) ==
                kWCryptoUnavailable,
            "software AES-GCM did not report unavailable");
    require(bytes_are_zero(output, sizeof(output)), "unavailable software AES-GCM output was not cleared");
}

static void test_aes256gcm_known_answer_and_interoperability(void)
{
    const uint8_t plaintext[16]                                       = {0};
    const uint8_t key[WCRYPTO_AES256GCM_KEY_SIZE]                     = {0};
    const uint8_t nonce[WCRYPTO_AES256GCM_NONCE_SIZE]                 = {0};
    const uint8_t expected[sizeof(plaintext) + WCRYPTO_AEAD_TAG_SIZE] = {
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    };
    const size_t backend_count = sizeof(aes256gcm_backends) / sizeof(aes256gcm_backends[0]);
    uint8_t      outputs[sizeof(aes256gcm_backends) / sizeof(aes256gcm_backends[0])][sizeof(expected)];
    bool         available[sizeof(aes256gcm_backends) / sizeof(aes256gcm_backends[0])] = {false};
    uint8_t      decrypted[sizeof(plaintext)];
    size_t       available_count = 0;

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        const aead_backend_t *backend = &aes256gcm_backends[producer];
        available[producer]           = aead_backend_is_available(backend);
        if (! available[producer])
        {
            continue;
        }
        ++available_count;
        require_backend(
            backend->encrypt(
                outputs[producer], sizeof(outputs[producer]), plaintext, sizeof(plaintext), NULL, 0, nonce, key) ==
                kWCryptoOk,
            backend->name,
            "AES-256-GCM known-answer encryption failed");
        require_backend_bytes_equal(outputs[producer],
                                    expected,
                                    sizeof(expected),
                                    backend->name,
                                    "AES-256-GCM known-answer ciphertext/tag mismatch");
    }

    if (available_count == 0)
    {
        require(! wCryptoAes256GcmIsAvailable(), "AES-256-GCM dispatcher availability disagrees with its backends");
        return;
    }

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        if (! available[producer])
        {
            continue;
        }
        for (size_t consumer = 0; consumer < backend_count; ++consumer)
        {
            if (! available[consumer])
            {
                continue;
            }
            const aead_backend_t *backend = &aes256gcm_backends[consumer];
            memset(decrypted, 0, sizeof(decrypted));
            require_backend(
                backend->decrypt(
                    decrypted, sizeof(decrypted), outputs[producer], sizeof(expected), NULL, 0, nonce, key) ==
                    kWCryptoOk,
                backend->name,
                "cross-backend AES-256-GCM decryption failed");
            require_backend_bytes_equal(
                decrypted, plaintext, sizeof(plaintext), backend->name, "cross-backend AES-256-GCM plaintext mismatch");
        }
    }
}

static void test_xchacha20poly1305(void)
{
    const char    plaintext[]                                           = "This is a secret message!";
    const char    ad[]                                                  = "Additional authenticated data";
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE]                        = {0x00};
    const uint8_t nonce[XCHACHA20POLY1305_NONCE_SIZE]                   = {0x01};
    const uint8_t expected[(sizeof(plaintext) - 1) + POLY1305_TAG_SIZE] = {
        0x3e, 0x51, 0x7a, 0xb2, 0xdf, 0x97, 0x45, 0x79, 0x36, 0xe7, 0x86, 0xf3, 0x96, 0x0c,
        0xda, 0x04, 0x3c, 0x9b, 0x3f, 0x38, 0xdd, 0xce, 0x59, 0x2b, 0x49, 0xd4, 0x0f, 0x6e,
        0x19, 0x66, 0xb7, 0x36, 0x32, 0x87, 0x5a, 0x73, 0x5f, 0x00, 0xb1, 0xb7, 0x3e,
    };
    uint8_t      outputs[sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0])][sizeof(expected)];
    uint8_t      decrypted[sizeof(plaintext) - 1] = {0};
    const size_t backend_count = sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0]);

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        const aead_backend_t *backend = &xchacha20poly1305_backends[producer];
        require_backend(backend->encrypt(outputs[producer],
                                         sizeof(outputs[producer]),
                                         (const uint8_t *) plaintext,
                                         sizeof(plaintext) - 1,
                                         (const uint8_t *) ad,
                                         sizeof(ad) - 1,
                                         nonce,
                                         key) == kWCryptoOk,
                        backend->name,
                        "XChaCha20-Poly1305 encryption failed");
        require_backend_bytes_equal(
            outputs[producer], expected, sizeof(expected), backend->name, "XChaCha20-Poly1305 vector mismatch");
    }

    for (size_t producer = 0; producer < backend_count; ++producer)
    {
        for (size_t consumer = 0; consumer < backend_count; ++consumer)
        {
            const aead_backend_t *backend = &xchacha20poly1305_backends[consumer];
            memoryZero(decrypted, sizeof(decrypted));
            require_backend(backend->decrypt(decrypted,
                                             sizeof(decrypted),
                                             outputs[producer],
                                             sizeof(expected),
                                             (const uint8_t *) ad,
                                             sizeof(ad) - 1,
                                             nonce,
                                             key) == kWCryptoOk,
                            backend->name,
                            "cross-backend XChaCha20-Poly1305 decryption failed");
            require_backend_bytes_equal(decrypted,
                                        (const uint8_t *) plaintext,
                                        sizeof(decrypted),
                                        backend->name,
                                        "cross-backend XChaCha20-Poly1305 plaintext mismatch");
        }
    }
}

int main(void)
{
    const uint8_t chacha_nonce[CHACHA20POLY1305_NONCE_SIZE]   = {0};
    const uint8_t xchacha_nonce[XCHACHA20POLY1305_NONCE_SIZE] = {0};
    const uint8_t aes_nonce[WCRYPTO_AES256GCM_NONCE_SIZE]     = {0};

    test_status_strings();
    test_secure_zero();
    test_secure_equal();
    test_global_lifecycle();

    test_hash_vectors();
    test_hash_contract();
    test_blake2s_unkeyed();
    test_blake2s_keyed();
    test_blake2s_lifecycle();
    test_blake2s_lengths_and_reuse();
    test_x25519();
    test_x25519_rejected_key();
    test_chacha20poly1305();
    test_chacha20poly1305_nonzero_prefix_and_interoperability();
    test_chacha20poly1305_nonce_prefix_sensitivity();
    test_aead_short_ciphertexts(chacha20poly1305_backends,
                                sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]),
                                chacha_nonce);
    test_aead_contract(chacha20poly1305_backends,
                       sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]),
                       chacha_nonce,
                       sizeof(chacha_nonce));
    test_aead_boundary_lengths(chacha20poly1305_backends,
                               sizeof(chacha20poly1305_backends) / sizeof(chacha20poly1305_backends[0]),
                               chacha_nonce);
    test_xchacha20poly1305();
    test_aead_short_ciphertexts(xchacha20poly1305_backends,
                                sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0]),
                                xchacha_nonce);
    test_aead_contract(xchacha20poly1305_backends,
                       sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0]),
                       xchacha_nonce,
                       sizeof(xchacha_nonce));
    test_aead_boundary_lengths(xchacha20poly1305_backends,
                               sizeof(xchacha20poly1305_backends) / sizeof(xchacha20poly1305_backends[0]),
                               xchacha_nonce);
    test_aead_short_ciphertexts(
        aes256gcm_backends, sizeof(aes256gcm_backends) / sizeof(aes256gcm_backends[0]), aes_nonce);
    test_aead_contract(
        aes256gcm_backends, sizeof(aes256gcm_backends) / sizeof(aes256gcm_backends[0]), aes_nonce, sizeof(aes_nonce));
    test_aead_boundary_lengths(
        aes256gcm_backends, sizeof(aes256gcm_backends) / sizeof(aes256gcm_backends[0]), aes_nonce);
    test_aes256gcm_known_answer_and_interoperability();
    test_unavailable_software_aes();
    wCryptoGlobalCleanup();
    wCryptoGlobalCleanup();
    return 0;
}
