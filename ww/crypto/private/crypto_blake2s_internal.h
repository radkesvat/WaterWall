#pragma once

#include "wcrypto.h"

#define WCRYPTO_BLAKE2S_ACTIVE_MAGIC UINT32_C(0x42325357)

typedef enum wcrypto_blake2s_implementation_e
{
    kWCryptoBlake2sImplementationNone = 0,
    kWCryptoBlake2sImplementationSoftware,
    kWCryptoBlake2sImplementationOpenSSL,
} wcrypto_blake2s_implementation_t;

typedef struct wcrypto_software_blake2s_ctx_s
{
    uint8_t  b[64];
    uint32_t h[8];
    uint32_t t[2];
    size_t   c;
    size_t   outlen;
} wcrypto_software_blake2s_ctx_t;

typedef struct wcrypto_openssl_blake2s_ctx_s
{
    struct evp_md_ctx_st  *md_ctx;
    struct evp_md_st      *md;
    struct evp_mac_ctx_st *mac_ctx;
    struct evp_mac_st     *mac;
    size_t                 outlen;
} wcrypto_openssl_blake2s_ctx_t;

typedef struct wcrypto_blake2s_internal_s
{
    uint32_t                         magic;
    wcrypto_blake2s_implementation_t implementation;
    size_t                           outlen;
    union {
        wcrypto_software_blake2s_ctx_t software;
        wcrypto_openssl_blake2s_ctx_t  openssl;
    } backend;
} wcrypto_blake2s_internal_t;

_Static_assert(sizeof(wcrypto_blake2s_internal_t) <= WCRYPTO_BLAKE2S_CONTEXT_BYTES,
               "WCRYPTO_BLAKE2S_CONTEXT_BYTES is too small");
_Static_assert(_Alignof(wcrypto_blake2s_ctx_t) >= _Alignof(wcrypto_blake2s_internal_t),
               "public BLAKE2s storage is under-aligned");

static inline wcrypto_blake2s_internal_t *wCryptoBlake2sInternal(wcrypto_blake2s_ctx_t *ctx)
{
    return (wcrypto_blake2s_internal_t *) (void *) ctx->storage;
}

static inline const wcrypto_blake2s_internal_t *wCryptoBlake2sInternalConst(const wcrypto_blake2s_ctx_t *ctx)
{
    return (const wcrypto_blake2s_internal_t *) (const void *) ctx->storage;
}
