/**
 * @file wcrypto.h
 * @brief Cryptographic functions and utilities.
 *
 * This file provides cryptographic functions including BLAKE2s hashing,
 * X25519 Diffie-Hellman key exchange, and AEAD encryption/decryption using
 * ChaCha20-Poly1305 and XChaCha20-Poly1305.
 *
 * The API supports multiple backends:
 *   - WCRYPTO_BACKEND_SODIUM / WCRYPTO_BACKEND_SOFTWARE using libsodium.
 *   - WCRYPTO_BACKEND_OPENSSL using OpenSSL.
 *
 * @note The inline functions use constant-time comparisons and secure memory zeroing
 *       to mitigate side-channel attacks.
 */

#pragma once
#include "wlibc.h"

#if defined (WCRYPTO_BACKEND_SODIUM) 

#include "sodium.h"
#endif





#define MD5_DIGEST_SIZE          16  /* 128 bits */
#define SHA1_DIGEST_SIZE         20  /* 160 bits */

#define SHA224_DIGEST_SIZE       28  /* 224 bits */
#define SHA256_DIGEST_SIZE       32  /* 256 bits */
#define SHA384_DIGEST_SIZE       48  /* 384 bits */
#define SHA512_DIGEST_SIZE       64  /* 512 bits */

#define SHA3_224_DIGEST_SIZE     28
#define SHA3_256_DIGEST_SIZE     32
#define SHA3_384_DIGEST_SIZE     48
#define SHA3_512_DIGEST_SIZE     64

typedef struct {
    uint8_t bytes[MD5_DIGEST_SIZE];
} md5_hash_t;

typedef struct {
    uint8_t bytes[SHA1_DIGEST_SIZE];
} sha1_hash_t;

typedef struct {
    uint8_t bytes[SHA224_DIGEST_SIZE];
} sha224_hash_t;

typedef struct {
    uint8_t bytes[SHA256_DIGEST_SIZE];
} sha256_hash_t;

typedef struct {
    uint8_t bytes[SHA384_DIGEST_SIZE];
} sha384_hash_t;

typedef struct {
    uint8_t bytes[SHA512_DIGEST_SIZE];
} sha512_hash_t;

typedef struct {
    uint8_t bytes[SHA3_224_DIGEST_SIZE];
} sha3_224_hash_t;

typedef struct {
    uint8_t bytes[SHA3_256_DIGEST_SIZE];
} sha3_256_hash_t;

typedef struct {
    uint8_t bytes[SHA3_384_DIGEST_SIZE];
} sha3_384_hash_t;

typedef struct {
    uint8_t bytes[SHA3_512_DIGEST_SIZE];
} sha3_512_hash_t;

/**
 * @brief Perform a single-shot MD5 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoMD5(md5_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA-1 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA-224 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA-256 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA-384 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA-512 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA3-224 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA3-256 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA3-384 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen);

/**
 * @brief Perform a single-shot SHA3-512 digest.
 *
 * @return 0 on success, non-zero on failure.
 */
int wCryptoSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen);






#if defined (WCRYPTO_BACKEND_SODIUM) || defined (WCRYPTO_BACKEND_SOFTWARE)

/**
 * @brief Context for BLAKE2s hash computations.
 *
 * Contains the internal state, buffering, and parameters.
 */
typedef struct
{
    uint8_t  b[64];   ///< Input buffer.
    uint32_t h[8];    ///< Chained state.
    uint32_t t[2];    ///< Total number of bytes hashed.
    size_t   c;       ///< Current buffer offset.
    size_t   outlen;  ///< Desired output digest length.
} blake2s_ctx_t;

#endif 

#if defined (WCRYPTO_BACKEND_OPENSSL) 

/**
 * @brief Concrete BLAKE2s context wrapper for the OpenSSL backend.
 *
 * OpenSSL exposes the underlying hash/MAC contexts as opaque types, so the
 * public backend-neutral API stores pointers to the active implementation.
 */
typedef struct
{
    struct evp_md_ctx_st  *md_ctx;
    struct evp_md_st      *md;
    struct evp_mac_ctx_st *mac_ctx;
    struct evp_mac_st     *mac;
    size_t                 outlen;
} blake2s_ctx_t;

#endif

/**
 * @brief Initialize a BLAKE2s hash context.
 *
 * @param ctx Pointer to a BLAKE2s context.
 * @param outlen Desired hash output length in bytes.
 * @param key Pointer to the key for keyed hashing (or NULL for unkeyed).
 * @param keylen Length of the key in bytes (0 if unkeyed).
 * @return 1 on success, 0 on failure.
 */
int blake2sInit(blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key, size_t keylen);

/**
 * @brief Update a BLAKE2s hash context with new data.
 *
 * @param ctx Pointer to an initialized BLAKE2s context.
 * @param in Pointer to the input data.
 * @param inlen Length of the input data in bytes.
 * @return 1 on success, 0 on failure.
 */
int blake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen);

/**
 * @brief Finalize the BLAKE2s hash and produce the digest.
 *
 * @param ctx Pointer to the BLAKE2s context.
 * @param out Buffer to receive the hash output.
 * @return 1 on success, 0 on failure.
 */
int blake2sFinal(blake2s_ctx_t *ctx, unsigned char *out);

/**
 * @brief Perform a single-shot BLAKE2s hash.
 *
 * This function combines initialization, updating, and finalization.
 *
 * @param out Buffer to receive the hash output.
 * @param outlen Desired output length in bytes.
 * @param key Optional key for keyed hashing (or NULL for unkeyed).
 * @param keylen Length of the key in bytes.
 * @param in Pointer to the input data.
 * @param inlen Length of the input data in bytes.
 * @return 1 on success, 0 on failure.
 */
int blake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen, const unsigned char *in,
            size_t inlen);

/**
 * @brief Perform an X25519 Diffie-Hellman key exchange.
 *
 * Computes the shared secret from a private key (scalar) and a public key (point).
 *
 * @param out 32-byte buffer to receive the shared secret.
 * @param scalar 32-byte private key.
 * @param point 32-byte public key.
 * @return 1 on success, 0 on failure.
 */
int performX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]);

/**
 * @brief Encrypt data using ChaCha20-Poly1305 AEAD.
 *
 * Encrypts and authenticates the input data.
 *
 * @param dst Destination buffer for the ciphertext appended with a 16-byte tag.
 * @param src Pointer to the plaintext data.
 * @param srclen Length of the plaintext data in bytes.
 * @param ad Pointer to additional authenticated data (can be NULL).
 * @param ad_len Length of the additional data.
 * @param nonce 12-byte unique nonce.
 * @param key 32-byte encryption key.
 * @return 1 on success, 0 on failure.
 */
int chacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                            size_t ad_len, const unsigned char *nonce, const unsigned char *key);

/**
 * @brief Decrypt and verify data using ChaCha20-Poly1305 AEAD.
 *
 * Decrypts the ciphertext and checks its authenticity.
 *
 * @param dst Destination buffer for the recovered plaintext.
 * @param src Pointer to the ciphertext (includes tag).
 * @param srclen Length of the ciphertext in bytes.
 * @param ad Pointer to additional authenticated data (can be NULL).
 * @param ad_len Length of the additional data.
 * @param nonce 12-byte unique nonce.
 * @param key 32-byte decryption key.
 * @return 1 on success (authentication valid), 0 on failure.
 */
int chacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                            size_t ad_len, const unsigned char *nonce, const unsigned char *key);

/**
 * @brief Check whether AES-256-GCM is available in the active crypto backend.
 *
 * @return 1 if available, 0 otherwise.
 */
int aes256gcmIsAvailable(void);

/**
 * @brief Encrypt data using AES-256-GCM AEAD.
 *
 * @param dst Destination buffer for ciphertext appended with a 16-byte tag.
 * @param src Pointer to plaintext.
 * @param src_len Plaintext size in bytes.
 * @param ad Pointer to additional authenticated data (can be NULL).
 * @param ad_len AAD length in bytes.
 * @param nonce 12-byte nonce.
 * @param key 32-byte key.
 * @return 0 on success, non-zero on failure.
 */
int aes256gcmEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                     size_t ad_len, const unsigned char *nonce, const unsigned char *key);

/**
 * @brief Decrypt and authenticate AES-256-GCM ciphertext.
 *
 * @param dst Destination buffer for plaintext.
 * @param src Pointer to ciphertext with trailing 16-byte tag.
 * @param src_len Ciphertext+tag size in bytes.
 * @param ad Pointer to additional authenticated data (can be NULL).
 * @param ad_len AAD length in bytes.
 * @param nonce 12-byte nonce.
 * @param key 32-byte key.
 * @return 0 on success, non-zero on failure.
 */
int aes256gcmDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len, const unsigned char *ad,
                     size_t ad_len, const unsigned char *nonce, const unsigned char *key);

/**
 * @brief Encrypt using XChaCha20-Poly1305 AEAD.
 *
 * Works similarly to chacha20poly1305Encrypt but uses a 24-byte nonce for extended nonce support.
 *
 * @param dst Destination buffer for the ciphertext appended with a tag.
 * @param src Pointer to the plaintext data.
 * @param srclen Length of the plaintext data in bytes.
 * @param ad Pointer to additional authenticated data (can be NULL).
 * @param ad_len Length of the additional data.
 * @param nonce 24-byte unique nonce.
 * @param key 32-byte encryption key.
 * @return 1 on success, 0 on failure.
 */
int xchacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t ad_len, const unsigned char *nonce, const unsigned char *key);

/**
 * @brief Decrypt using XChaCha20-Poly1305 AEAD.
 *
 * Works similarly to chacha20poly1305Decrypt but uses a 24-byte nonce.
 *
 * @param dst Destination buffer for the recovered plaintext.
 * @param src Pointer to the ciphertext (includes tag).
 * @param srclen Length of the ciphertext in bytes.
 * @param ad Pointer to additional authenticated data (can be NULL).
 * @param ad_len Length of the additional data.
 * @param nonce 24-byte unique nonce.
 * @param key 32-byte decryption key.
 * @return 1 on success (authentication valid), 0 on failure.
 */
int xchacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t ad_len, const unsigned char *nonce, const unsigned char *key);

/**
 * @brief Securely zero out memory.
 *
 * Clears the buffer to prevent data leakage in a constant-time manner.
 *
 * @param dest Pointer to the memory buffer.
 * @param len Number of bytes to zero.
 */
static inline void wCryptoZero(void *dest, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char*)dest;
    while (len--)
    {
        *p++ = 0;
    }
}

/**
 * @brief Compare two memory buffers in constant time.
 *
 * Performs a constant-time comparison to prevent timing attacks.
 *
 * @param a Pointer to the first buffer.
 * @param b Pointer to the second buffer.
 * @param size Size of the buffers in bytes.
 * @return true if the buffers are equal; false otherwise.
 */
static inline bool wCryptoEqual(const void *a, const void *b, size_t size)
{
    const unsigned char *p1 = (const unsigned char*)a;
    const unsigned char *p2 = (const unsigned char*)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < size; i++)
    {
        diff |= p1[i] ^ p2[i];
    }
    return diff == 0;
}
