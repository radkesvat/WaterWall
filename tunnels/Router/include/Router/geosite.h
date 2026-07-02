#pragma once

#include "wwapi.h"

#include "common/geosite_types.h"

typedef struct router_geosite_domain_key_s
{
    const char *value;
    uint32_t    len;
    hash_t      hash;
} router_geosite_domain_key_t;

static inline hash_t routerGeositeHashBytes(const char *value, uint32_t len)
{
    return calcHashBytesSeed(value, len, 0);
}

static inline uint64_t routerGeositeDomainKeyHash(const router_geosite_domain_key_t *key)
{
    return key->hash;
}

static inline bool routerGeositeDomainKeyEquals(const router_geosite_domain_key_t *left,
                                                const router_geosite_domain_key_t *right)
{
    return left->len == right->len && memoryCompare(left->value, right->value, left->len) == 0;
}

static inline void routerGeositeDomainKeyDrop(router_geosite_domain_key_t *key)
{
    if (key->value != NULL)
    {
        memoryFree((void *) key->value);
    }
    key->value = NULL;
    key->len   = 0;
    key->hash  = 0;
}

#define i_type     router_geosite_domain_set_t  // NOLINT
#define i_key      router_geosite_domain_key_t  // NOLINT
#define i_hash     routerGeositeDomainKeyHash   // NOLINT
#define i_eq       routerGeositeDomainKeyEquals // NOLINT
#define i_keydrop  routerGeositeDomainKeyDrop   // NOLINT
#define i_no_clone                              // NOLINT
#include "stc/hset.h"
#undef i_no_clone
#undef i_keydrop
#undef i_eq
#undef i_hash
#undef i_key
#undef i_type

#include "stc/cregex.h"

typedef struct router_geosite_compiled_list_s
{
    char *name;

    /*
     * Shared by all workers after Router creation. Runtime matching treats
     * these STC sets as immutable and only calls contains()/read helpers. If a
     * future STC update adds read-side mutation, caching, or lazy maintenance to
     * lookup APIs, GeoSite matching must add synchronization or switch to an
     * explicitly immutable representation.
     */
    router_geosite_domain_set_t full_domains;
    router_geosite_domain_set_t root_domains;

    char   **plain_patterns;
    uint32_t plain_patterns_count;

    cregex  *regex_patterns;
    uint32_t regex_patterns_count;
} router_geosite_compiled_list_t;

typedef struct router_geosite_host_cache_s
{
    bool     ready;
    bool     valid;
    char     host[UINT8_MAX + 1U];
    uint32_t host_len;
    uint8_t  suffix_offsets[UINT8_MAX];
    uint32_t suffix_offsets_count;
} router_geosite_host_cache_t;

bool     routerGeositeNormalizeHost(const uint8_t *host, uint32_t host_len, char *out, uint32_t *out_len);
void     routerGeositeHostCachePrepare(router_geosite_host_cache_t *cache, const uint8_t *host, uint32_t host_len);
uint32_t routerGeositeBuildSuffixOffsets(const char *host, uint32_t host_len, uint8_t *offsets,
                                         uint32_t offsets_capacity);
bool     routerGeositeCompiledListMatches(const router_geosite_compiled_list_t *list, const char *host,
                                          uint32_t host_len);
bool     routerGeositeCompiledListMatchesPrepared(const router_geosite_compiled_list_t *list,
                                                  const router_geosite_host_cache_t    *host);
