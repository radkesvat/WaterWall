#pragma once

#include "wcrypto.h"

WCRYPTO_MUST_USE wcrypto_status_t wCryptoValidateHash(const void *out, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoValidateBlake2sInit(const void *ctx, size_t outlen, const unsigned char *key,
                                                             size_t keylen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoValidateBlake2sUpdate(const void *ctx, const unsigned char *in, size_t inlen);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoValidateX25519(const unsigned char *out, const unsigned char *scalar,
                                                        const unsigned char *point);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoValidateAeadEncrypt(unsigned char *dst, size_t dst_capacity,
                                                             const unsigned char *src, size_t src_len,
                                                             const unsigned char *ad, size_t ad_len,
                                                             const unsigned char *nonce, const unsigned char *key,
                                                             size_t *output_len);
WCRYPTO_MUST_USE wcrypto_status_t wCryptoValidateAeadDecrypt(unsigned char *dst, size_t dst_capacity,
                                                             const unsigned char *src, size_t src_len,
                                                             const unsigned char *ad, size_t ad_len,
                                                             const unsigned char *nonce, const unsigned char *key,
                                                             size_t *output_len);

bool wCryptoIsInitialized(void);
