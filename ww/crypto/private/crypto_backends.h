#pragma once

#include "wcrypto.h"

#if defined(WCRYPTO_HAS_SOFTWARE_HASH)
int wCryptoSoftwareMD5(md5_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoSoftwareSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoSoftwareSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoSoftwareSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen);
#endif

#if defined(WCRYPTO_HAS_SOFTWARE_BLAKE2S)
int wCryptoSoftwareBlake2sInit(blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key, size_t keylen);
int wCryptoSoftwareBlake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen);
int wCryptoSoftwareBlake2sFinal(blake2s_ctx_t *ctx, unsigned char *out);
int wCryptoSoftwareBlake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen,
                           const unsigned char *in, size_t inlen);
#endif

#if defined(WCRYPTO_HAS_SOFTWARE_X25519)
int wCryptoSoftwareX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]);
#endif

#if defined(WCRYPTO_HAS_SOFTWARE_CHACHA20POLY1305)
int wCryptoSoftwareChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                           const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                           const unsigned char *key);
int wCryptoSoftwareChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                           const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                           const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_SOFTWARE_XCHACHA20POLY1305)
int wCryptoSoftwareXChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                            const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                            const unsigned char *key);
int wCryptoSoftwareXChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                            const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                            const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_SOFTWARE_AES256GCM)
int wCryptoSoftwareAES256GCMIsAvailable(void);
int wCryptoSoftwareAES256GCMEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                    const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                    const unsigned char *key);
int wCryptoSoftwareAES256GCMDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                    const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                    const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_SODIUM_HASH)
int wCryptoSodiumSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoSodiumSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen);
#endif

#if defined(WCRYPTO_HAS_SODIUM_X25519)
int wCryptoSodiumX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]);
#endif

#if defined(WCRYPTO_HAS_SODIUM_CHACHA20POLY1305)
int wCryptoSodiumChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                         const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                         const unsigned char *key);
int wCryptoSodiumChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                         const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                         const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_SODIUM_XCHACHA20POLY1305)
int wCryptoSodiumXChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                          const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                          const unsigned char *key);
int wCryptoSodiumXChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                          const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                          const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_SODIUM_AES256GCM)
int wCryptoSodiumAES256GCMIsAvailable(void);
int wCryptoSodiumAES256GCMEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                  const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                  const unsigned char *key);
int wCryptoSodiumAES256GCMDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                  const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                  const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_HASH)
int wCryptoOpenSSLMD5(md5_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA1(sha1_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA384(sha384_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA512(sha512_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA3_224(sha3_224_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA3_256(sha3_256_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA3_384(sha3_384_hash_t *out, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLSHA3_512(sha3_512_hash_t *out, const unsigned char *in, size_t inlen);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_BLAKE2S)
int wCryptoOpenSSLBlake2sInit(blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key, size_t keylen);
int wCryptoOpenSSLBlake2sUpdate(blake2s_ctx_t *ctx, const unsigned char *in, size_t inlen);
int wCryptoOpenSSLBlake2sFinal(blake2s_ctx_t *ctx, unsigned char *out);
int wCryptoOpenSSLBlake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen,
                          const unsigned char *in, size_t inlen);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_X25519)
int wCryptoOpenSSLX25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_CHACHA20POLY1305)
int wCryptoOpenSSLChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                          const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                          const unsigned char *key);
int wCryptoOpenSSLChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                          const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                          const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_XCHACHA20POLY1305)
int wCryptoOpenSSLXChacha20Poly1305Encrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                           const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                           const unsigned char *key);
int wCryptoOpenSSLXChacha20Poly1305Decrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                           const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                           const unsigned char *key);
#endif

#if defined(WCRYPTO_HAS_OPENSSL_AES256GCM)
int wCryptoOpenSSLAES256GCMIsAvailable(void);
int wCryptoOpenSSLAES256GCMEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                   const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                   const unsigned char *key);
int wCryptoOpenSSLAES256GCMDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                   const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                   const unsigned char *key);
#endif
