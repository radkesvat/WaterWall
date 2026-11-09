#include "DnsLineClient/internal.h"

/*
 * Per-worker bounded LRU cache. Every instance belongs to exactly one worker
 * and is touched only on that worker, so there is no locking. Keys are the
 * normalized (lowercased) domain plus the query-type set.
 */

static uint32_t dnslineclientCacheHash(const dnslineclient_cache_t *cache, const char *domain, uint8_t qmask)
{
    uint32_t hash = 2166136261U ^ cache->seed; // seeded FNV-1a
    for (const unsigned char *p = (const unsigned char *) domain; *p != '\0'; ++p)
    {
        hash ^= *p;
        hash *= 16777619U;
    }
    hash ^= qmask;
    hash *= 16777619U;
    return hash;
}

void dnslineclientCacheInit(dnslineclient_cache_t *cache, uint32_t capacity)
{
    memoryZero(cache, sizeof(*cache));
    cache->capacity = capacity;
    cache->seed     = fastRand32();
}

static void dnslineclientCacheEntryFree(dnslineclient_cache_entry_t *entry)
{
    memoryFree(entry->addrs);
    memoryFree(entry);
}

void dnslineclientCacheDestroy(dnslineclient_cache_t *cache)
{
    dnslineclient_cache_entry_t *entry = cache->lru_head;
    while (entry != NULL)
    {
        dnslineclient_cache_entry_t *next = entry->lru_next;
        dnslineclientCacheEntryFree(entry);
        entry = next;
    }
    memoryFree(cache->buckets);
    uint32_t capacity = cache->capacity;
    memoryZero(cache, sizeof(*cache));
    cache->capacity = capacity;
}

static void dnslineclientCacheLruUnlink(dnslineclient_cache_t *cache, dnslineclient_cache_entry_t *entry)
{
    if (entry->lru_prev != NULL)
    {
        entry->lru_prev->lru_next = entry->lru_next;
    }
    else
    {
        cache->lru_head = entry->lru_next;
    }
    if (entry->lru_next != NULL)
    {
        entry->lru_next->lru_prev = entry->lru_prev;
    }
    else
    {
        cache->lru_tail = entry->lru_prev;
    }
    entry->lru_prev = entry->lru_next = NULL;
}

static void dnslineclientCacheLruPushFront(dnslineclient_cache_t *cache, dnslineclient_cache_entry_t *entry)
{
    entry->lru_prev = NULL;
    entry->lru_next = cache->lru_head;
    if (cache->lru_head != NULL)
    {
        cache->lru_head->lru_prev = entry;
    }
    cache->lru_head = entry;
    if (cache->lru_tail == NULL)
    {
        cache->lru_tail = entry;
    }
}

static void dnslineclientCacheRemove(dnslineclient_cache_t *cache, dnslineclient_cache_entry_t *entry)
{
    dnslineclient_cache_entry_t **link = &cache->buckets[entry->hash & (cache->nbuckets - 1)];
    while (*link != entry)
    {
        link = &(*link)->hash_next;
    }
    *link = entry->hash_next;
    dnslineclientCacheLruUnlink(cache, entry);
    --cache->count;
    dnslineclientCacheEntryFree(entry);
}

static dnslineclient_cache_entry_t *dnslineclientCacheFind(dnslineclient_cache_t *cache, const char *domain,
                                                           uint8_t qmask, uint32_t hash)
{
    if (cache->buckets == NULL)
    {
        return NULL;
    }
    for (dnslineclient_cache_entry_t *entry = cache->buckets[hash & (cache->nbuckets - 1)]; entry != NULL;
         entry                              = entry->hash_next)
    {
        if (entry->hash == hash && entry->qmask == qmask && stringCompare(entry->domain, domain) == 0)
        {
            return entry;
        }
    }
    return NULL;
}

const dnslineclient_cache_entry_t *dnslineclientCacheLookup(dnslineclient_cache_t *cache, const char *domain,
                                                            uint8_t qmask, uint64_t now_ms)
{
    if (cache->capacity == 0)
    {
        return NULL;
    }

    uint32_t                     hash  = dnslineclientCacheHash(cache, domain, qmask);
    dnslineclient_cache_entry_t *entry = dnslineclientCacheFind(cache, domain, qmask, hash);
    if (entry == NULL)
    {
        return NULL;
    }
    if (now_ms >= entry->expire_ms)
    {
        dnslineclientCacheRemove(cache, entry);
        return NULL;
    }
    dnslineclientCacheLruUnlink(cache, entry);
    dnslineclientCacheLruPushFront(cache, entry);
    return entry;
}

void dnslineclientCacheInsert(dnslineclient_cache_t *cache, const char *domain, uint8_t qmask,
                              const dns_resolved_addr_t *addrs, size_t naddrs, uint32_t ttl_s, uint64_t now_ms)
{
    if (cache->capacity == 0 || naddrs == 0 || ttl_s == 0)
    {
        return;
    }

    if (cache->buckets == NULL)
    {
        uint32_t nbuckets = 16;
        while (nbuckets < cache->capacity && nbuckets < kDnsLineClientMaxCacheBuckets)
        {
            nbuckets <<= 1U;
        }
        cache->buckets  = memoryAllocateZero(nbuckets * sizeof(*cache->buckets));
        cache->nbuckets = nbuckets;
    }

    uint32_t                     hash     = dnslineclientCacheHash(cache, domain, qmask);
    dnslineclient_cache_entry_t *existing = dnslineclientCacheFind(cache, domain, qmask, hash);
    if (existing != NULL)
    {
        dnslineclientCacheRemove(cache, existing);
    }
    while (cache->count >= cache->capacity && cache->lru_tail != NULL)
    {
        dnslineclientCacheRemove(cache, cache->lru_tail);
    }

    size_t                       domain_len = stringLength(domain);
    dnslineclient_cache_entry_t *entry      = memoryAllocateZero(sizeof(*entry) + domain_len + 1);
    memoryCopy(entry->domain, domain, domain_len + 1);
    entry->addrs = memoryAllocate(naddrs * sizeof(*addrs));
    memoryCopy(entry->addrs, addrs, naddrs * sizeof(*addrs));
    entry->naddrs    = naddrs;
    entry->qmask     = qmask;
    entry->hash      = hash;
    entry->expire_ms = now_ms + (uint64_t) ttl_s * 1000U;

    dnslineclient_cache_entry_t **bucket = &cache->buckets[hash & (cache->nbuckets - 1)];
    entry->hash_next                     = *bucket;
    *bucket                              = entry;
    dnslineclientCacheLruPushFront(cache, entry);
    ++cache->count;
}
