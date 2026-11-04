#pragma once

/*
 * DnsLineClient internals: worker/query/cache structures, the pure c-ares
 * record codec and the per-worker LRU cache. Exposed for unit tests; tunnels
 * use only dns_line_client.h.
 */

#include "DnsLineClient/dns_line_client.h"

#include <ares_dns_record.h>

enum
{
    kDnsLineClientMaxDomainLength = 253, // presentation length without the trailing dot
    kDnsLineClientMaxLabelLength  = 63,
    kDnsLineClientMaxSlots        = 2,  // one datagram per query type (A, AAAA)
    kDnsLineClientMaxAddrsPerType = 32, // addresses kept from one answer
    kDnsLineClientMaxCnameHops    = 16, // CNAME links followed inside one message
    kDnsLineClientMaxCacheBuckets = 65536,
    kDnsLineClientMaxInflightPerWorker = 4096 // distinct names resolving at once on one worker
};

/* Query-type set. */
enum
{
    kDnsLineClientQtypeA    = 1U << 0,
    kDnsLineClientQtypeAAAA = 1U << 1
};

/* ------------------------------------------------------------------------ */
/* codec                                                                    */
/* ------------------------------------------------------------------------ */

/*
 * Lowercase `domain` into `out` (at least kDnsLineClientMaxDomainLength + 1
 * bytes), dropping one trailing dot. Returns false for an empty name, a name
 * that is too long, an empty or over-long label, or an IP literal.
 */
bool dnslineclientNormalizeDomain(const char *domain, char *out);

/* Encode one RD=1 question for `domain` (normalized). `*out` must be released with ares_free_string(). */
int dnslineclientCodecBuildQuery(const char *domain, uint16_t id, ares_dns_rec_type_t qtype, unsigned char **out,
                                 size_t *out_len);

typedef enum dnslineclient_parse_result_e
{
    kDnsLineClientParseIgnored = 0, // stray, spoofed, oversized or unrelated datagram; the try continues
    kDnsLineClientParseAnswered     // `out` settles the slot with `slot` index
} dnslineclient_parse_result_e;

typedef struct dnslineclient_answer_s
{
    uint32_t             slot;   // index into the expected ids/qtypes arrays
    int                  status; // ARES_SUCCESS (naddrs > 0), ARES_ENODATA, ARES_ENOTFOUND, ARES_ESERVFAIL, ...
    uint32_t             ttl;    // clamped seconds, meaningful for ARES_SUCCESS
    size_t               naddrs;
    dns_resolved_addr_t *addrs; // memoryAllocate()d, NULL when naddrs == 0; release with memoryFree()
} dnslineclient_answer_t;

/*
 * Parse one response datagram against the outstanding questions
 * (`ids[i]`, `qtypes[i]` for `domain`). A datagram that is larger than
 * kDnsLineClientMaxResponseBytes, has no matching id, is not a response (QR=0)
 * or whose question does not match is ignored. A matching datagram with TC=1
 * or that c-ares cannot parse answers ARES_EBADRESP.
 */
dnslineclient_parse_result_e dnslineclientCodecParseResponse(const unsigned char *buf, size_t len, const char *domain,
                                                             const uint16_t *ids, const ares_dns_rec_type_t *qtypes,
                                                             uint32_t nslots, uint32_t min_ttl, uint32_t max_ttl,
                                                             dnslineclient_answer_t *out);

/* ------------------------------------------------------------------------ */
/* cache                                                                    */
/* ------------------------------------------------------------------------ */

typedef struct dnslineclient_cache_entry_s dnslineclient_cache_entry_t;

struct dnslineclient_cache_entry_s
{
    dnslineclient_cache_entry_t *hash_next;
    dnslineclient_cache_entry_t *lru_prev; // towards most recently used
    dnslineclient_cache_entry_t *lru_next; // towards least recently used
    uint64_t                     expire_ms;
    uint32_t                     hash;
    uint8_t                      qmask;
    size_t                       naddrs;
    dns_resolved_addr_t         *addrs;
    char                         domain[];
};

typedef struct dnslineclient_cache_s
{
    dnslineclient_cache_entry_t **buckets; // allocated on first insert
    uint32_t                      nbuckets;
    uint32_t                      count;
    uint32_t                      capacity; // 0 disables the cache
    dnslineclient_cache_entry_t  *lru_head;
    dnslineclient_cache_entry_t  *lru_tail;
    uint32_t                      seed; // per-cache hash seed, so bucket collisions cannot be precomputed
} dnslineclient_cache_t;

void dnslineclientCacheInit(dnslineclient_cache_t *cache, uint32_t capacity);
void dnslineclientCacheDestroy(dnslineclient_cache_t *cache);
/* Returns a live entry (and marks it most recently used) or NULL; expired entries are dropped. */
const dnslineclient_cache_entry_t *dnslineclientCacheLookup(dnslineclient_cache_t *cache, const char *domain,
                                                            uint8_t qmask, uint64_t now_ms);
/* Copies `addrs`. ttl_s == 0 or naddrs == 0 stores nothing. Evicts the least recently used entry when full. */
void dnslineclientCacheInsert(dnslineclient_cache_t *cache, const char *domain, uint8_t qmask,
                              const dns_resolved_addr_t *addrs, size_t naddrs, uint32_t ttl_s, uint64_t now_ms);

/* ------------------------------------------------------------------------ */
/* runtime                                                                  */
/* ------------------------------------------------------------------------ */

typedef struct dnslineclient_waiter_s dnslineclient_waiter_t;

struct dnslineclient_waiter_s
{
    dnslineclient_waiter_t *next;
    line_t                 *line; // borrowed, one lineRef() held until settlement
    LineDnsResolveFn        cb;
    tunnel_t               *t;
    void                   *userdata;
};

typedef struct dnslineclient_slot_s
{
    uint16_t             id;
    ares_dns_rec_type_t  qtype;
    bool                 settled;
    int                  status;
    uint32_t             ttl;
    size_t               naddrs;
    dns_resolved_addr_t *addrs;
    sbuf_t              *pending; // encoded query not yet sent (Pause)
} dnslineclient_slot_t;

typedef enum dnslineclient_query_phase_e
{
    kDnsLineClientPhaseChain = 0, // attempts over injected lines
    kDnsLineClientPhaseCore,      // waiting for the worker c-ares fallback
    kDnsLineClientPhaseDone
} dnslineclient_query_phase_e;

typedef struct dnslineclient_worker_s dnslineclient_worker_t;

struct dnslineclient_query_s
{
    dnslineclient_t            *client;
    dnslineclient_worker_t     *worker;
    dnslineclient_query_t      *prev; // worker in-flight inventory
    dnslineclient_query_t      *next;
    wid_t                       wid;
    uint32_t                    refs; // inventory membership + reentrancy holds + pending c-ares fallback
    uint8_t                     qmask;
    bool                        in_inventory;
    bool                        running; // queryRun() active
    bool                        kick;    // queryRun() must look again
    dnslineclient_query_phase_e phase;
    dnslineclient_waiter_t     *waiters;
    dnslineclient_waiter_t    **waiters_tail;
    uint32_t                    attempts; // started attempts
    uint32_t                    server_base; // worker's preferred server when the query started
    uint32_t                    server_idx;  // server of the current attempt
    int                         last_status;

    // current attempt
    line_t              *line; // owned normal line, NULL between attempts
    wtimer_t            *timer;
    bool                 upstream_open; // Init sent toward next and no Finish exchanged yet
    bool                 paused;        // downstream Pause from the route
    uint32_t             nslots;
    dnslineclient_slot_t slots[kDnsLineClientMaxSlots];

    char domain[kDnsLineClientMaxDomainLength + 1];
};

struct dnslineclient_worker_s
{
    dnslineclient_query_t *inflight;
    dnslineclient_cache_t  cache;
    uint32_t               inflight_count;
    uint32_t               preferred_server; // first server for new queries; moves past a failing one
    bool                   closed; // quiesced or stopped: no admission, no new attempts or timers
};

struct dnslineclient_s
{
    dnslineclient_config_t  cfg;
    tunnel_t               *host;
    dnslineclient_open_fn   open;
    dnslineclient_detach_fn detach;
    wid_t                   workers_count;
    dnslineclient_worker_t  workers[];
};

/* Query-type set used for `strategy`. */
uint8_t dnslineclientQmaskForStrategy(enum domain_strategy strategy);

/* In-flight query on worker `wid` for (normalized domain, qmask), or NULL. */
dnslineclient_query_t *dnslineclientFindInflight(dnslineclient_t *client, wid_t wid, const char *domain, uint8_t qmask);
