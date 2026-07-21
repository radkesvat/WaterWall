/**
 * @file wcrypto.h
 * @brief Backend-neutral cryptographic operations.
 *
 * Every fallible operation returns wcrypto_status_t: kWCryptoOk is the only
 * success value.  Call wCryptoGlobalInit() once during single-threaded startup
 * before using an operation and wCryptoGlobalCleanup() after all users stop.
 *
 * AEAD functions support disjoint buffers and exact in-place operation.  Other
 * partial overlap is unsupported.  On a failure after the destination has been
 * validated, the deterministic output region is cleared.
 */

#pragma once

#include "wlibc.h"

#if defined(__GNUC__) || defined(__clang__)
#define WCRYPTO_MUST_USE __attribute__((warn_unused_result))
#else
#define WCRYPTO_MUST_USE
#endif

typedef enum wcrypto_status_e
{
    kWCryptoOk                   = 0,
    kWCryptoInvalidArgument      = -1,
    kWCryptoAuthenticationFailed = -2,
    kWCryptoUnavailable          = -3,
    kWCryptoInputTooLarge        = -4,
    kWCryptoInvalidState         = -5,
    kWCryptoRejectedKey          = -6,
    kWCryptoBackendFailed        = -7,
} wcrypto_status_t;

#define WCRYPTO_AEAD_TAG_SIZE                16
#define WCRYPTO_CHACHA20POLY1305_KEY_SIZE    32
#define WCRYPTO_CHACHA20POLY1305_NONCE_SIZE  12
#define WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE 24
#define WCRYPTO_AES256GCM_KEY_SIZE           32
#define WCRYPTO_AES256GCM_NONCE_SIZE         12
#define WCRYPTO_X25519_KEY_SIZE              32
#define WCRYPTO_BLAKE2S_MAX_DIGEST_SIZE      32
#define WCRYPTO_BLAKE2S_MAX_KEY_SIZE         32
#define WCRYPTO_BLAKE2S_CONTEXT_BYTES        256
/* Maximum raw buffer accepted by any AEAD backend. Encryption plaintext is
 * limited to this value minus the tag so its result remains decryptable. */
#define WCRYPTO_AEAD_MAX_INPUT_SIZE         ((size_t) INT_MAX)
#define WCRYPTO_BLAKE2S_CONTEXT_INITIALIZER {0}

/* Existing digest names remain part of the public contract. MD5 and SHA-1 are
 * legacy protocol-compatibility primitives and must not be used for new
 * authentication, signature, or password-storage designs. */
#define MD5_DIGEST_SIZE      16
#define SHA1_DIGEST_SIZE     20
#define SHA224_DIGEST_SIZE   28
#define SHA256_DIGEST_SIZE   32
#define SHA384_DIGEST_SIZE   48
#define SHA512_DIGEST_SIZE   64
#define SHA3_224_DIGEST_SIZE 28
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_384_DIGEST_SIZE 48
#define SHA3_512_DIGEST_SIZE 64

typedef struct
{
    uint8_t bytes[MD5_DIGEST_SIZE];
} md5_hash_t;
typedef struct
{
    uint8_t bytes[SHA1_DIGEST_SIZE];
} sha1_hash_t;
typedef struct
{
    uint8_t bytes[SHA224_DIGEST_SIZE];
} sha224_hash_t;
typedef struct
{
    uint8_t bytes[SHA256_DIGEST_SIZE];
} sha256_hash_t;
typedef struct
{
    uint8_t bytes[SHA384_DIGEST_SIZE];
} sha384_hash_t;
typedef struct
{
    uint8_t bytes[SHA512_DIGEST_SIZE];
} sha512_hash_t;
typedef struct
{
    uint8_t bytes[SHA3_224_DIGEST_SIZE];
} sha3_224_hash_t;
typedef struct
{
    uint8_t bytes[SHA3_256_DIGEST_SIZE];
} sha3_256_hash_t;
typedef struct
{
    uint8_t bytes[SHA3_384_DIGEST_SIZE];
} sha3_384_hash_t;
typedef struct
{
    uint8_t bytes[SHA3_512_DIGEST_SIZE];
} sha3_512_hash_t;

typedef union wcrypto_blake2s_ctx_u {
    max_align_t   alignment;
    unsigned char storage[WCRYPTO_BLAKE2S_CONTEXT_BYTES];
} wcrypto_blake2s_ctx_t;

const char *wCryptoStatusString(wcrypto_status_t status);

WCRYPTO_MUST_USE wcrypto_status_t wCryptoGlobalInit(void);
void                              wCryptoGlobalCleanup(void);

WCRYPTO_MUST_USE wcrypto_status_t wCryptoMD5(md5_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen);

/* Contexts must start with WCRYPTO_BLAKE2S_CONTEXT_INITIALIZER. Final requires
 * the same output length passed to Init; that explicit extent is cleared on a
 * finalization failure. Final and Destroy return the context to the zero state.
 * Reinitializing an active context is an invalid-state error. */
WCRYPTO_MUST_USE wcrypto_status_t wCryptoBlake2sInit(wcrypto_blake2s_ctx_t *ctx, size_t outlen,
                                                     const unsigned char *key, size_t keylen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoBlake2sUpdate(wcrypto_blake2s_ctx_t *ctx, const unsigned char *in,
                                                       size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoBlake2sFinal(wcrypto_blake2s_ctx_t *ctx, unsigned char *out, size_t outlen);
void                              wCryptoBlake2sDestroy(wcrypto_blake2s_ctx_t *ctx);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoBlake2s(unsigned char *out, size_t outlen, const unsigned char *key,
                                                 size_t keylen, const unsigned char *in, size_t inlen);

WCRYPTO_MUST_USE wcrypto_status_t wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                                const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                                const unsigned char point[WCRYPTO_X25519_KEY_SIZE]);

WCRYPTO_MUST_USE wcrypto_status_t wCryptoChaCha20Poly1305Encrypt(
    unsigned char *dst, size_t dst_capacity, const unsigned char *src, size_t src_len, const unsigned char *ad,
    size_t ad_len, const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
    const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoChaCha20Poly1305Decrypt(
    unsigned char *dst, size_t dst_capacity, const unsigned char *src, size_t src_len, const unsigned char *ad,
    size_t ad_len, const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
    const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);

bool                              wCryptoAes256GcmIsAvailable(void);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoAes256GcmEncrypt(unsigned char *dst, size_t dst_capacity,
                                                          const unsigned char *src, size_t src_len,
                                                          const unsigned char *ad, size_t ad_len,
                                                          const unsigned char nonce[WCRYPTO_AES256GCM_NONCE_SIZE],
                                                          const unsigned char key[WCRYPTO_AES256GCM_KEY_SIZE]);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoAes256GcmDecrypt(unsigned char *dst, size_t dst_capacity,
                                                          const unsigned char *src, size_t src_len,
                                                          const unsigned char *ad, size_t ad_len,
                                                          const unsigned char nonce[WCRYPTO_AES256GCM_NONCE_SIZE],
                                                          const unsigned char key[WCRYPTO_AES256GCM_KEY_SIZE]);

WCRYPTO_MUST_USE wcrypto_status_t wCryptoXChaCha20Poly1305Encrypt(
    unsigned char *dst, size_t dst_capacity, const unsigned char *src, size_t src_len, const unsigned char *ad,
    size_t ad_len, const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
    const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoXChaCha20Poly1305Decrypt(
    unsigned char *dst, size_t dst_capacity, const unsigned char *src, size_t src_len, const unsigned char *ad,
    size_t ad_len, const unsigned char nonce[WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE],
    const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);

static inline void wCryptoZero(void *dest, size_t len)
{
    memorySecureZero(dest, len);
}

/* Return true exactly when both fixed-length byte strings are equal.  The
 * comparison work does not depend on the contents; a and b must be valid for
 * size bytes unless size is zero. */
bool wCryptoEqual(const void *a, const void *b, size_t size);
