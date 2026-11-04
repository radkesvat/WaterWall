#pragma once

/*
 * DnsLineClient
 * -------------
 * Internal (non-user) component that resolves a domain by sending plain DNS
 * wire-format queries over an ordinary WaterWall UDP line, so the chain (for
 * example Router rules with "protocol": "dns") decides where the query goes.
 *
 * c-ares is used only as a codec (ares_dns_record.h). No socket is opened here.
 *
 * Ownership model
 * - Each attempt creates one owned normal UDP line with lineCreate() on the
 *   waiter line's worker, from the host tunnel chain's line pools. DnsLineClient
 *   is that line's creator and the only caller of lineDestroy() for it.
 * - The line is injected through a host tunnel (DomainResolver). The host binds
 *   the query to its own per-line state in `open`, then sends Init toward the
 *   route. All later upstream traffic goes through tunnelNextUpStream*(host, l).
 *   Downstream callbacks arrive at the host (Router's prev, or a standalone
 *   resolver's own next side) which forwards them to dnslineclientOnLine*().
 * - Waiter lines are borrowed: a waiter holds one lineRef() until it settles.
 *   Results are delivered only while the waiter line is alive, never
 *   synchronously from dnslineclientResolve(), and never for ARES_ECANCELLED
 *   (same contract as lineResolveDomainServiceAsync()).
 * - Worker shutdown: the host calls dnslineclientWorkerQuiesce() from its
 *   onWorkerQuiesce and dnslineclientWorkerStop() from its onWorkerStop on the
 *   owner worker. dnslineclientDestroy() runs on the main thread from onDestroy.
 */

#include "wwapi.h"

#include <ares.h>

enum
{
    kDnsLineClientMaxServers       = 8,
    kDnsLineClientMaxResponseBytes = 4096,
    kDnsLineClientDefaultPort      = 53,
    kDnsLineClientDefaultTimeoutMs = 2000,
    kDnsLineClientMinTimeoutMs     = 100,
    kDnsLineClientMaxTimeoutMs     = 60000,
    kDnsLineClientDefaultTries     = 2,
    kDnsLineClientMaxTries         = 16,
    kDnsLineClientDefaultCacheSize = 4096,
    kDnsLineClientMaxCacheSize     = 1048576,
    kDnsLineClientDefaultMinTtl    = 30,
    kDnsLineClientDefaultMaxTtl    = 3600,
    kDnsLineClientMaxTtlLimit      = 604800
};

typedef enum dnslineclient_mode_e
{
    kDnsLineClientModeCore  = 0, // today's worker c-ares channel (default)
    kDnsLineClientModeChain = 1  // DNS over an injected WaterWall UDP line
} dnslineclient_mode_e;

typedef struct dnslineclient_server_s
{
    ip_addr_t ip;   // IPv4 or IPv6 literal only
    uint16_t  port; // host byte order, default 53
} dnslineclient_server_t;

typedef struct dnslineclient_config_s
{
    dnslineclient_server_t servers[kDnsLineClientMaxServers];
    uint32_t               servers_count;
    uint32_t               timeout_ms; // per try
    uint32_t               tries;      // total attempts across servers, rotating
    uint32_t               cache_size; // entries per worker; 0 disables the cache
    uint32_t               min_ttl;    // seconds
    uint32_t               max_ttl;    // seconds, >= min_ttl
    bool                   fallback_to_core;
} dnslineclient_config_t;

typedef struct dnslineclient_s       dnslineclient_t;
typedef struct dnslineclient_query_s dnslineclient_query_t;

/*
 * Host hooks (implemented by DomainResolver).
 * open:   bind `query` to the host's per-line state for `l`, then send upstream
 *         Init toward the route. May destroy the line before returning; the
 *         caller holds a reference and re-checks lineIsAlive().
 * detach: clear the host's per-line binding for `l` (zero its state) before the
 *         owner sends Finish upstream / destroys the line, or after the host
 *         delivered a downstream Finish. Idempotent.
 */
typedef void (*dnslineclient_open_fn)(tunnel_t *host, line_t *l, dnslineclient_query_t *query);
typedef void (*dnslineclient_detach_fn)(tunnel_t *host, line_t *l);

/*
 * Parse the DNS keys found directly inside `object` ("mode", "servers",
 * "timeout-ms", "tries", "cache-size", "min-ttl", "max-ttl",
 * "fallback-to-core"); other keys are ignored. `object` may be NULL (defaults,
 * mode core). Wrong type or out-of-range values log LOGF naming
 * "<json_path>-><key>" and return false. "servers" is required and non-empty
 * when mode is "chain"; domain names are rejected; optional ":port" (IPv6 as
 * "[addr]:port").
 */
bool dnslineclientConfigParse(const cJSON *object, const char *json_path, dnslineclient_mode_e *out_mode,
                              dnslineclient_config_t *out_cfg);

/* True when `key` is one of the DNS keys dnslineclientConfigParse() reads. A
 * dedicated "dns" object (Router) uses it to reject typos instead of silently
 * falling back to core DNS. */
bool dnslineclientConfigIsKnownKey(const char *key);

/* Startup, main thread, after the worker count is known. Never returns NULL. */
dnslineclient_t *dnslineclientCreate(const dnslineclient_config_t *cfg, tunnel_t *host, dnslineclient_open_fn open,
                                     dnslineclient_detach_fn detach);
/* Main thread, after every worker ran dnslineclientWorkerStop(). */
void dnslineclientDestroy(dnslineclient_t *client);

/* Owner worker `wid`: close admission and stop this worker's timers. */
void dnslineclientWorkerQuiesce(dnslineclient_t *client, wid_t wid);
/* Owner worker `wid`: close in-flight lines, cancel waiters (ARES_ECANCELLED,
 * no callback), free the worker's cache. Idempotent. */
void dnslineclientWorkerStop(dnslineclient_t *client, wid_t wid);

/*
 * Resolve `domain` for the borrowed waiter line `waiter` (must run on its
 * worker). `strategy` selects the query types: only-ipv4 -> A, only-ipv6 ->
 * AAAA, otherwise A and AAAA. Returns ARES_SUCCESS when accepted; `cb` then runs
 * later exactly once unless the waiter dies or the request is cancelled. Any
 * other return value means `cb` will never run.
 */
int dnslineclientResolve(dnslineclient_t *client, line_t *waiter, const char *domain, enum domain_strategy strategy,
                         LineDnsResolveFn cb, tunnel_t *t, void *userdata);

/* Downstream events of an injected line, forwarded by the host. */
void dnslineclientOnLineEst(dnslineclient_query_t *query, line_t *l);
void dnslineclientOnLinePayload(dnslineclient_query_t *query, line_t *l, sbuf_t *buf); // takes ownership
void dnslineclientOnLineFinish(dnslineclient_query_t *query, line_t *l);               // host already detached
void dnslineclientOnLinePause(dnslineclient_query_t *query, line_t *l);
void dnslineclientOnLineResume(dnslineclient_query_t *query, line_t *l);
