#pragma once
#include "wlibc.h"

// Context structure for BLAKE2s hash function operations
typedef struct evp_mac_ctx_st blake2s_ctx_t;

// Initialize BLAKE2s hash context
// outlen: desired hash output length in bytes
// key: optional key for keyed hashing (NULL for unkeyed)
// keylen: length of key (0 for unkeyed)
// Returns: 1 on success, 0 on failure
int blake2sInit(blake2s_ctx_t **ctx, size_t outlen, const unsigned char *key, size_t keylen);

// Update BLAKE2s hash context with new data
// ctx: initialized BLAKE2s context
// in: input data to hash
// inlen: length of input data
// Returns: 1 on success, 0 on failure
int blake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen);

// Finalize BLAKE2s hash and get output
// ctx: BLAKE2s context
// out: buffer to receive hash output
// Returns: 1 on success, 0 on failure
int blake2sFinal(blake2s_ctx_t *ctx, unsigned char *out);

// Convenience function for single-shot BLAKE2s hashing
// Combines Init/Update/Final into one call
// Returns: 1 on success, 0 on failure
int blake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen, const unsigned char *in,
            size_t inlen);

// Perform X25519 Diffie-Hellman key exchange
// out: 32-byte buffer for computed shared secret
// scalar: 32-byte private key
// point: 32-byte public key
// Returns: 1 on success, 0 on failure
int performX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]);

// Encrypt data using ChaCha20-Poly1305 AEAD
// dst: destination buffer for encrypted data + 16-byte tag
// src: source data to encrypt
// srclen: length of source data
// ad: additional authenticated data (can be NULL)
// adlen: length of additional data
// nonce: 12-byte unique nonce
// key: 32-byte encryption key
// Returns: 1 on success, 0 on failure
int chacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                            size_t adlen, const unsigned char *nonce, const unsigned char *key);

// Decrypt and verify data using ChaCha20-Poly1305 AEAD
// Parameters same as encrypt function
// Returns: 1 on success (valid decryption), 0 on failure (authentication failed)
int chacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                            size_t adlen, const unsigned char *nonce, const unsigned char *key);

// Encrypt using XChaCha20-Poly1305 (extended nonce version)
// Same as chacha20poly1305Encrypt but uses 24-byte nonce
// Provides better security for randomly generated nonces
int xchacha20poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key);

// Decrypt using XChaCha20-Poly1305 (extended nonce version)
// Same as chacha20poly1305Decrypt but uses 24-byte nonce
int xchacha20poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t srclen, const unsigned char *ad,
                             size_t adlen, const unsigned char *nonce, const unsigned char *key);
