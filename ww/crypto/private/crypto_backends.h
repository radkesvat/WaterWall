#pragma once

#include "private/crypto_blake2s_internal.h"
#include "private/crypto_config.h"
#include "wcrypto.h"

#if defined(WCRYPTO_HAS_SOFTWARE_HASH)
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareMD5(md5_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareSHA1(sha1_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareSHA224(sha224_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareSHA256(sha256_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareSHA384(sha384_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareSHA512(sha512_hash_t *, const unsigned char *, size_t);
#endif

#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareBlake2sInit(wcrypto_software_blake2s_ctx_t *, size_t,
                                                             const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareBlake2sUpdate(wcrypto_software_blake2s_ctx_t *, const unsigned char *,
                                                               size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareBlake2sFinal(wcrypto_software_blake2s_ctx_t *, unsigned char *,
                                                              size_t);
void                              wCryptoSoftwareBlake2sDestroy(wcrypto_software_blake2s_ctx_t *);
#endif

#if defined(WCRYPTO_HAS_SOFTWARE_X25519)
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSoftwareX25519(unsigned char[WCRYPTO_X25519_KEY_SIZE],
                                                        const unsigned char[WCRYPTO_X25519_KEY_SIZE],
                                                        const unsigned char[WCRYPTO_X25519_KEY_SIZE]);
#endif

#define WCRYPTO_DECLARE_AEAD_BACKEND(prefix, nonce_size)                                                               \
    WCRYPTO_MUST_USE wcrypto_status_t prefix##Encrypt(unsigned char *,                                                 \
                                                      size_t,                                                          \
                                                      const unsigned char *,                                           \
                                                      size_t,                                                          \
                                                      const unsigned char *,                                           \
                                                      size_t,                                                          \
                                                      const unsigned char[nonce_size],                                 \
                                                      const unsigned char[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);         \
    WCRYPTO_MUST_USE wcrypto_status_t prefix##Decrypt(unsigned char *,                                                 \
                                                      size_t,                                                          \
                                                      const unsigned char *,                                           \
                                                      size_t,                                                          \
                                                      const unsigned char *,                                           \
                                                      size_t,                                                          \
                                                      const unsigned char[nonce_size],                                 \
                                                      const unsigned char[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])

#if defined(WCRYPTO_HAS_SOFTWARE_CHACHA20POLY1305)
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoSoftwareChacha20Poly1305, WCRYPTO_CHACHA20POLY1305_NONCE_SIZE);
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_XCHACHA20POLY1305)
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoSoftwareXChacha20Poly1305, WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE);
#endif
#if defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
bool wCryptoSoftwareAES256GCMIsAvailable(void);
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoSoftwareAES256GCM, WCRYPTO_AES256GCM_NONCE_SIZE);
#endif

#if defined(WCRYPTO_HAS_SODIUM_HASH)
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSodiumSHA256(sha256_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSodiumSHA512(sha512_hash_t *, const unsigned char *, size_t);
#endif
#if defined(WCRYPTO_HAS_SODIUM_X25519)
WCRYPTO_MUST_USE wcrypto_status_t wCryptoSodiumX25519(unsigned char[WCRYPTO_X25519_KEY_SIZE],
                                                      const unsigned char[WCRYPTO_X25519_KEY_SIZE],
                                                      const unsigned char[WCRYPTO_X25519_KEY_SIZE]);
#endif
#if defined(WCRYPTO_HAS_SODIUM_CHACHA20POLY1305)
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoSodiumChacha20Poly1305, WCRYPTO_CHACHA20POLY1305_NONCE_SIZE);
#endif
#if defined(WCRYPTO_HAS_SODIUM_XCHACHA20POLY1305)
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoSodiumXChacha20Poly1305, WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE);
#endif
#if defined(WCRYPTO_HAS_SODIUM_AES256GCM)
bool wCryptoSodiumAES256GCMIsAvailable(void);
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoSodiumAES256GCM, WCRYPTO_AES256GCM_NONCE_SIZE);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_HASH)
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLMD5(md5_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA1(sha1_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA224(sha224_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA256(sha256_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA384(sha384_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA512(sha512_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA3_224(sha3_224_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA3_256(sha3_256_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA3_384(sha3_384_hash_t *, const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLSHA3_512(sha3_512_hash_t *, const unsigned char *, size_t);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
bool                              wCryptoOpenSSLBlake2sIsAvailable(size_t, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLBlake2sInit(wcrypto_openssl_blake2s_ctx_t *, size_t,
                                                            const unsigned char *, size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLBlake2sUpdate(wcrypto_openssl_blake2s_ctx_t *, const unsigned char *,
                                                              size_t);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLBlake2sFinal(wcrypto_openssl_blake2s_ctx_t *, unsigned char *, size_t);
void                              wCryptoOpenSSLBlake2sDestroy(wcrypto_openssl_blake2s_ctx_t *);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_X25519)
WCRYPTO_MUST_USE wcrypto_status_t wCryptoOpenSSLX25519(unsigned char[WCRYPTO_X25519_KEY_SIZE],
                                                       const unsigned char[WCRYPTO_X25519_KEY_SIZE],
                                                       const unsigned char[WCRYPTO_X25519_KEY_SIZE]);
#endif
#if defined(WCRYPTO_HAS_OPENSSL_CHACHA20POLY1305)
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoOpenSSLChacha20Poly1305, WCRYPTO_CHACHA20POLY1305_NONCE_SIZE);
#endif
#if defined(WCRYPTO_HAS_OPENSSL_XCHACHA20POLY1305)
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoOpenSSLXChacha20Poly1305, WCRYPTO_XCHACHA20POLY1305_NONCE_SIZE);
#endif
#if defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
bool wCryptoOpenSSLAES256GCMIsAvailable(void);
WCRYPTO_DECLARE_AEAD_BACKEND(wCryptoOpenSSLAES256GCM, WCRYPTO_AES256GCM_NONCE_SIZE);
#endif

#undef WCRYPTO_DECLARE_AEAD_BACKEND
