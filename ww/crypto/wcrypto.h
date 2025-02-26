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

#if defined (WCRYPTO_BACKEND_SODIUM) || defined (WCRYPTO_BACKEND_SOFTWARE)

#include "sodium.h"

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
 * @brief OpenSSL EVP_MAC context typedef for BLAKE2s.
 */
typedef struct evp_mac_ctx_st blake2s_ctx_t;

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
