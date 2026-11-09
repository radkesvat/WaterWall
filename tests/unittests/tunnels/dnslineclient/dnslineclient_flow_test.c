/*
 * Covers: DnsLineClient runtime with real pooled lines: injected UDP line shape, A+AAAA exchange, coalescing,
 * deferred delivery, cache hits, stray datagrams, pipe-backed (splice) replies, Pause/Resume, timeout rotation, route Finish (also synchronous
 * inside Init), NXDOMAIN, core fallback, worker quiesce/stop cancellation and delivery-message cancellation.
 * Setup: Worker-zero fixture with a real event loop. A minimal host tunnel binds the query in its line state and
 * forwards downstream events; a scripted route records upstream callbacks. Worker messages, the worker c-ares
 * entry point and the monotonic clock are linker seams.
 * Limits: One worker; no Router/DomainResolver (the integration cases cover those).
 * CTest: waterwall.dnslineclient_flow_unit
 */
#include "DnsLineClient/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/protocols/splice_source.h"

#include <unistd.h>

typedef struct host_lstate_s
{
    dnslineclient_query_t *query;
} host_lstate_t;

typedef struct captured_msg_s
{
    WorkerMessageCallback        cb;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
} captured_msg_t;

enum
{
    kMaxMsgs     = 32,
    kMaxSent     = 16,
    kMaxResults  = 16,
    kMaxRouteLns = 16
};

static twf_worker_env_t env;
static twf_line_pool_t  lines;
static tunnel_chain_t  *chain;
static tunnel_t        *host, *route;
static dnslineclient_t *client;

static captured_msg_t msgs[kMaxMsgs];
static unsigned       nmsgs;

static uint64_t now_us;

// route observations
static line_t  *route_lines[kMaxRouteLns];
static unsigned route_inits, route_fins;
static sbuf_t  *sent[kMaxSent];
static line_t  *sent_line[kMaxSent];
static unsigned nsent;
static bool     finish_in_init, pause_in_init;

// results
typedef struct result_s
{
    line_t             *line;
    void               *userdata;
    int                 status;
    size_t              naddrs;
    dns_resolved_addr_t first;
} result_t;
static result_t results[kMaxResults];
static unsigned nresults;

// core fallback seam
static dns_resolve_cb core_cb;
static void          *core_userdata;
static unsigned       core_calls;

/* ------------------------------------------------------------------------ */
/* seams                                                                    */
/* ------------------------------------------------------------------------ */

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    twfRequire(wid == 0 && arg2 == NULL && arg3 == NULL && nmsgs < kMaxMsgs, "unexpected worker message");
    msgs[nmsgs++] = (captured_msg_t){.cb = cb, .cleanup = cleanup, .arg1 = arg1};
    return kWorkerMessageSubmitAccepted;
}

int __wrap_workerResolveDomainServiceAsync(wid_t wid, const char *domain, const char *service, int socktype,
                                           dns_resolve_cb cb, void *userdata);
int __wrap_workerResolveDomainServiceAsync(wid_t wid, const char *domain, const char *service, int socktype,
                                           dns_resolve_cb cb, void *userdata)
{
    discard service;
    discard socktype;
    twfRequire(wid == 0 && stringCompare(domain, "example.test") == 0, "fallback asked for the wrong name");
    ++core_calls;
    core_cb       = cb;
    core_userdata = userdata;
    return ARES_SUCCESS;
}

uint64_t __wrap_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void)
{
    return now_us;
}

static void pumpMessages(void)
{
    unsigned n = nmsgs;
    nmsgs      = 0;
    for (unsigned i = 0; i < n; ++i)
    {
        msgs[i].cb(&env.worker, msgs[i].arg1, NULL, NULL);
    }
}

static void cancelMessages(void)
{
    unsigned n = nmsgs;
    nmsgs      = 0;
    for (unsigned i = 0; i < n; ++i)
    {
        msgs[i].cleanup(msgs[i].arg1, NULL, NULL, kWorkerMessageCancelQuiesced);
    }
}

static void advanceMs(uint32_t ms)
{
    now_us += (uint64_t) ms * 1000U;
    twfRequire(wloopProcessEvents(env.loop, 0) >= 0, "event-loop dispatch failed");
}

/* ------------------------------------------------------------------------ */
/* host + route                                                             */
/* ------------------------------------------------------------------------ */

static void hostOpen(tunnel_t *t, line_t *l, dnslineclient_query_t *query)
{
    host_lstate_t *ls = lineGetState(l, t);
    ls->query         = query;
    tunnelNextUpStreamInit(t, l);
}

static void hostDetach(tunnel_t *t, line_t *l)
{
    host_lstate_t *ls = lineGetState(l, t);
    ls->query         = NULL;
}

static void hostFinD(tunnel_t *t, line_t *l)
{
    host_lstate_t         *ls = lineGetState(l, t);
    dnslineclient_query_t *q  = ls->query;
    twfRequire(q != NULL, "downstream Finish on an unbound line");
    hostDetach(t, l);
    dnslineclientOnLineFinish(q, l);
}

static void hostPayloadD(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    host_lstate_t *ls = lineGetState(l, t);
    twfRequire(ls->query != NULL, "downstream payload on an unbound line");
    dnslineclientOnLinePayload(ls->query, l, buf);
}

static void hostPauseD(tunnel_t *t, line_t *l)
{
    host_lstate_t *ls = lineGetState(l, t);
    dnslineclientOnLinePause(ls->query, l);
}

static void hostResumeD(tunnel_t *t, line_t *l)
{
    host_lstate_t *ls = lineGetState(l, t);
    dnslineclientOnLineResume(ls->query, l);
}

static void routeInit(tunnel_t *t, line_t *l)
{
    twfRequire(route_inits < kMaxRouteLns, "too many route Inits");
    lineRef(l); // keeps the allocation distinct so later checks observe logical death
    route_lines[route_inits++] = l;
    if (pause_in_init)
    {
        tunnelPrevDownStreamPause(t, l);
    }
    if (finish_in_init)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

static void routePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(nsent < kMaxSent, "too many datagrams");
    sent_line[nsent] = l;
    sent[nsent++]    = buf;
}

static void routeFin(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++route_fins;
}

static void onResolved(tunnel_t *t, line_t *l, void *userdata, int status, const char *error,
                       const dns_resolved_addr_t *addrs, size_t naddrs)
{
    discard error;
    twfRequire(t == host && lineIsAlive(l) && nresults < kMaxResults, "delivery for a dead line or wrong tunnel");
    results[nresults] = (result_t){.line = l, .userdata = userdata, .status = status, .naddrs = naddrs};
    if (naddrs > 0)
    {
        results[nresults].first = addrs[0];
    }
    ++nresults;
}

/* ------------------------------------------------------------------------ */
/* helpers                                                                  */
/* ------------------------------------------------------------------------ */

static dnslineclient_config_t baseConfig(void)
{
    dnslineclient_mode_e   mode;
    dnslineclient_config_t cfg;
    cJSON *json = cJSON_Parse("{\"mode\":\"chain\",\"servers\":[\"192.0.2.53\",\"[2001:db8::53]:5353\"],"
                              "\"timeout-ms\":200,\"tries\":3,\"min-ttl\":1,\"max-ttl\":60}");
    twfRequire(dnslineclientConfigParse(json, "Test", &mode, &cfg), "base config");
    cJSON_Delete(json);
    return cfg;
}

static void begin(const char *name, dnslineclient_config_t cfg)
{
    twfSetCase(name);
    now_us = UINT64_C(5000000000);
    twfWorkerEnvSetup(&env, 4096, 16);

    host  = tunnelCreate(NULL, 0, sizeof(host_lstate_t));
    route = tunnelCreate(NULL, 0, 0);
    tunnelBind(host, route);
    host->chain_index  = 0;
    route->chain_index = 1;
    host->fnFinD       = hostFinD;
    host->fnPayloadD   = hostPayloadD;
    host->fnPauseD     = hostPauseD;
    host->fnResumeD    = hostResumeD;
    route->fnInitU     = routeInit;
    route->fnPayloadU  = routePayload;
    route->fnFinU      = routeFin;

    twfLinePoolSetup(&lines, host->lstate_size, 32);
    chain                = memoryAllocateZero(sizeof(*chain) + sizeof(generic_pool_t *));
    chain->workers_count = 1;
    chain->line_pools[0] = lines.pools[0];
    host->chain          = chain;
    route->chain         = chain;

    client = dnslineclientCreate(&cfg, host, hostOpen, hostDetach);
    nmsgs = route_inits = route_fins = nsent = nresults = core_calls = 0;
    finish_in_init = pause_in_init = false;
    core_cb                        = NULL;
}

static void end(void)
{
    dnslineclientWorkerQuiesce(client, 0);
    dnslineclientWorkerStop(client, 0);
    twfRequire(nmsgs == 0, "messages left behind");
    dnslineclientDestroy(client);
    for (unsigned i = 0; i < nsent; ++i)
    {
        lineReuseBuffer(sent_line[i], sent[i]);
    }
    nsent = 0;
    for (unsigned i = 0; i < route_inits; ++i)
    {
        twfRequire(! lineIsAlive(route_lines[i]), "attempt line survived worker stop");
        lineUnref(route_lines[i]);
    }
    twfRequire(wloopNTimers(env.loop) == 0, "timers left behind");
    memoryFree(chain);
    twfLinePoolTeardown(&lines);
    tunnelDestroy(route);
    tunnelDestroy(host);
    twfWorkerEnvTeardown(&env);
}

static line_t *newWaiter(void)
{
    return twfLinePoolCreateLine(&lines);
}

static void dropWaiter(line_t *l)
{
    lineDestroy(l);
}

static void requireRouteLine(line_t *l, bool v6_server)
{
    address_context_t *dest = lineGetDestinationAddressContext(l);
    twfRequire(addresscontextIsResolverOrigin(dest), "resolver-origin flag missing on injected line");
    twfRequire(dest->proto_udp && ! dest->proto_tcp && addresscontextIsIp(dest), "injected line is not UDP to an IP");
    if (v6_server)
        twfRequire(addresscontextIsIpv6(dest) && dest->port == 5353, "second server not used");
    else
        twfRequire(addresscontextIsIpv4(dest) && dest->port == 53, "first server not used");
}

/* Decode a sent query datagram. */
static uint16_t sentQuery(unsigned index, ares_dns_rec_type_t *qtype)
{
    ares_dns_record_t *rec = NULL;
    twfRequire(ares_dns_parse(sbufGetRawPtr(sent[index]), sbufGetLength(sent[index]), 0, &rec) == ARES_SUCCESS,
               "sent datagram is not DNS");
    const char *name = NULL;
    twfRequire(ares_dns_record_query_get(rec, 0, &name, qtype, NULL) == ARES_SUCCESS &&
                   stringCompare(name, "example.test") == 0 && (ares_dns_record_get_flags(rec) & ARES_FLAG_RD) != 0,
               "sent query fields");
    uint16_t id = ares_dns_record_get_id(rec);
    ares_dns_record_destroy(rec);
    return id;
}

#if WW_HAVE_SPLICE
/* A stream carrier can hand the reply back with its bytes still in a kernel pipe. */
static sbuf_t *spliceDatagram(const unsigned char *wire, uint32_t len)
{
    sbuf_t *buf = twfTrackAcquired(testSpliceSourceBuffer(256, len));
    twfRequire(buf != NULL && write(sbufSpliceMetadata(buf).pipefd[1], wire, len) == (ssize_t) len,
               "populate private pipe input");
    buf->capacity = buf->l_pad + len;
    sbufSetLength(buf, len);
    return buf;
}
#endif

static void respondAs(line_t *l, uint16_t id, ares_dns_rec_type_t qtype, ares_dns_rcode_t rcode, const char *addr,
                      bool splice)
{
    ares_dns_record_t *rec = NULL;
    twfRequire(ares_dns_record_create(&rec, id, ARES_FLAG_QR | ARES_FLAG_RD | ARES_FLAG_RA, ARES_OPCODE_QUERY, rcode) ==
                   ARES_SUCCESS,
               "record create");
    twfRequire(ares_dns_record_query_add(rec, "example.test", qtype, ARES_CLASS_IN) == ARES_SUCCESS, "query add");
    if (addr != NULL)
    {
        ares_dns_rr_t *rr = NULL;
        twfRequire(ares_dns_record_rr_add(&rr, rec, ARES_SECTION_ANSWER, "example.test", qtype, ARES_CLASS_IN, 120) ==
                       ARES_SUCCESS,
                   "rr add");
        if (qtype == ARES_REC_TYPE_A)
        {
            struct in_addr a;
            inet_pton(AF_INET, addr, &a);
            ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &a);
        }
        else
        {
            struct ares_in6_addr a6;
            inet_pton(AF_INET6, addr, &a6);
            ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &a6);
        }
    }
    unsigned char *wire = NULL;
    size_t         len  = 0;
    twfRequire(ares_dns_write(rec, &wire, &len) == ARES_SUCCESS, "write");
    ares_dns_record_destroy(rec);

    sbuf_t *buf = NULL;
#if WW_HAVE_SPLICE
    if (splice)
        buf = spliceDatagram(wire, (uint32_t) len);
#else
    twfRequire(! splice, "splice reply requested without splice support");
#endif
    if (buf == NULL)
    {
        buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
        sbufSetLength(buf, (uint32_t) len);
        sbufWrite(buf, wire, (uint32_t) len);
    }
    ares_free_string(wire);
    tunnelPrevDownStreamPayload(route, l, buf);
}

static void respond(line_t *l, uint16_t id, ares_dns_rec_type_t qtype, ares_dns_rcode_t rcode, const char *addr)
{
    respondAs(l, id, qtype, rcode, addr, false);
}

static void recycleSent(void)
{
    for (unsigned i = 0; i < nsent; ++i)
    {
        lineReuseBuffer(sent_line[i], sent[i]);
    }
    nsent = 0;
}

/* ------------------------------------------------------------------------ */
/* scenarios                                                                */
/* ------------------------------------------------------------------------ */

static void testSuccessCoalesceCache(void)
{
    begin("A+AAAA exchange, coalescing, deferred delivery and cache hit", baseConfig());
    line_t *w1 = newWaiter(), *w2 = newWaiter(), *w3 = newWaiter();

    twfRequire(dnslineclientResolve(client, w1, "Example.TEST.", kDsPreferIpV4, onResolved, host, (void *) 1) ==
                   ARES_SUCCESS,
               "resolve rejected");
    twfRequire(route_inits == 1 && nsent == 2 && nresults == 0 && nmsgs == 0, "attempt shape");
    line_t *l = route_lines[0];
    requireRouteLine(l, false);
    twfRequire(dnslineclientFindInflight(client, 0, "example.test", 3) != NULL, "query not in the inventory");

    twfRequire(dnslineclientResolve(client, w2, "example.test", kDsPreferIpV6, onResolved, host, (void *) 2) ==
                   ARES_SUCCESS,
               "coalesced resolve rejected");
    twfRequire(route_inits == 1, "identical query was not coalesced");

    ares_dns_rec_type_t t0, t1;
    uint16_t            id0 = sentQuery(0, &t0), id1 = sentQuery(1, &t1);
    twfRequire(t0 == ARES_REC_TYPE_A && t1 == ARES_REC_TYPE_AAAA && id0 != id1, "A and AAAA with distinct ids");

    respond(l, (uint16_t) (id0 ^ id1 ^ 0x5A5A), ARES_REC_TYPE_A, ARES_RCODE_NOERROR, "203.0.113.9"); // stray
    respond(l, id1, ARES_REC_TYPE_AAAA, ARES_RCODE_NOERROR, "2001:db8::7");
    twfRequire(lineIsAlive(l) && route_fins == 0 && nmsgs == 0, "settled before both types answered");
    respond(l, id0, ARES_REC_TYPE_A, ARES_RCODE_NOERROR, "203.0.113.7");
    twfRequire(! lineIsAlive(l) || route_fins == 1, "attempt line not closed");
    twfRequire(route_fins == 1 && nmsgs == 2 && nresults == 0, "delivery was not deferred");
    twfRequire(dnslineclientFindInflight(client, 0, "example.test", 3) == NULL, "query left in the inventory");

    pumpMessages();
    twfRequire(nresults == 2 && results[0].status == ARES_SUCCESS && results[0].naddrs == 2 &&
                   results[0].first.family == AF_INET && results[0].first.ttl == 60 && results[1].line == w2,
               "waiters got the wrong result");

    // Cache hit: no line, deferred delivery.
    twfRequire(dnslineclientResolve(client, w3, "example.test", kDsPreferIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "cached resolve rejected");
    twfRequire(route_inits == 1 && nresults == 2 && nmsgs == 1, "cache hit not deferred or opened a line");
    pumpMessages();
    twfRequire(nresults == 3 && results[2].naddrs == 2 && results[2].line == w3, "cache hit result");

    // Dead waiter: the result is not delivered.
    line_t *w4 = newWaiter();
    lineRef(w4);
    twfRequire(dnslineclientResolve(client, w4, "example.test", kDsPreferIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "cached resolve rejected");
    dropWaiter(w4);
    pumpMessages();
    twfRequire(nresults == 3, "delivered to a dead waiter");
    lineUnref(w4);

    recycleSent();
    dropWaiter(w1);
    dropWaiter(w2);
    dropWaiter(w3);
    end();
}

static void testTimeoutRotationAndFinish(void)
{
    begin("timeout and route Finish rotate servers, then fail", baseConfig());
    line_t *w = newWaiter();
    twfRequire(dnslineclientResolve(client, w, "example.test", kDsOnlyIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "resolve rejected");
    twfRequire(route_inits == 1 && nsent == 1 && wloopNTimers(env.loop) == 1, "first attempt");
    requireRouteLine(route_lines[0], false);

    advanceMs(150);
    twfRequire(route_inits == 1, "timed out early");
    advanceMs(100);
    twfRequire(route_inits == 2 && route_fins == 1 && ! lineIsAlive(route_lines[0]), "timeout did not rotate");
    requireRouteLine(route_lines[1], true);

    // The route closes attempt 2: no upstream Finish back, rotate to server 0.
    tunnelPrevDownStreamFinish(route, route_lines[1]);
    twfRequire(route_inits == 3 && route_fins == 1, "remote Finish did not rotate or was answered upstream");
    requireRouteLine(route_lines[2], false);

    advanceMs(250);
    twfRequire(route_inits == 3 && route_fins == 2 && nmsgs == 1, "tries not honoured");
    pumpMessages();
    twfRequire(nresults == 1 && results[0].status == ARES_ETIMEOUT, "final status");
    recycleSent();
    dropWaiter(w);
    end();
}

static void testSynchronousFinish(void)
{
    begin("route finishing inside Init fails every try without synchronous delivery", baseConfig());
    finish_in_init = true;
    line_t *w      = newWaiter();
    twfRequire(dnslineclientResolve(client, w, "example.test", kDsPreferIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "resolve rejected");
    twfRequire(route_inits == 3 && route_fins == 0 && nsent == 0 && nresults == 0 && nmsgs == 1,
               "synchronous failures not settled through a deferred message");
    for (unsigned i = 0; i < route_inits; ++i)
        twfRequire(! lineIsAlive(route_lines[i]), "attempt line survived its Finish");
    pumpMessages();
    twfRequire(nresults == 1 && results[0].status == ARES_ECONNREFUSED, "final status");
    dropWaiter(w);
    end();
}

#if WW_HAVE_SPLICE
static void testSpliceReply(void)
{
    begin("pipe-backed replies from a stream carrier are read, not dropped", baseConfig());
    line_t *w = newWaiter();
    twfRequire(dnslineclientResolve(client, w, "example.test", kDsPreferIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "resolve rejected");
    twfRequire(route_inits == 1 && nsent == 2, "attempt shape");
    line_t             *l = route_lines[0];
    ares_dns_rec_type_t t0, t1;
    uint16_t            id0 = sentQuery(0, &t0), id1 = sentQuery(1, &t1);

    respondAs(l, id1, t1, ARES_RCODE_NOERROR, t1 == ARES_REC_TYPE_A ? "203.0.113.8" : "2001:db8::8", true);
    twfRequire(lineIsAlive(l) && route_fins == 0, "settled before both types answered");
    respondAs(l, id0, t0, ARES_RCODE_NOERROR, t0 == ARES_REC_TYPE_A ? "203.0.113.8" : "2001:db8::8", true);
    twfRequire(route_fins == 1 && nmsgs == 1, "pipe-backed replies did not settle the attempt");
    pumpMessages();
    twfRequire(nresults == 1 && results[0].status == ARES_SUCCESS && results[0].naddrs == 2, "final result");
    dropWaiter(w);
    end();
}
#endif

static void testPauseNxdomain(void)
{
    begin("Pause holds the queries; NXDOMAIN settles without rotation", baseConfig());
    pause_in_init = true;
    line_t *w     = newWaiter();
    twfRequire(dnslineclientResolve(client, w, "example.test", kDsPreferIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "resolve rejected");
    twfRequire(route_inits == 1 && nsent == 0, "query sent during Pause");
    tunnelPrevDownStreamResume(route, route_lines[0]);
    twfRequire(nsent == 2, "Resume did not release the queries");
    ares_dns_rec_type_t t0;
    uint16_t            id0 = sentQuery(0, &t0);
    respond(route_lines[0], id0, t0, ARES_RCODE_NXDOMAIN, NULL);
    twfRequire(route_inits == 1 && route_fins == 1 && nmsgs == 1, "NXDOMAIN did not settle at once");
    pumpMessages();
    twfRequire(nresults == 1 && results[0].status == ARES_ENOTFOUND, "NXDOMAIN status");
    recycleSent();
    dropWaiter(w);
    end();
}

static void testFallback(void)
{
    dnslineclient_config_t cfg = baseConfig();
    cfg.tries                  = 1;
    cfg.fallback_to_core       = true;
    begin("exhausted chain falls back to the worker resolver once", cfg);
    line_t *w = newWaiter();
    twfRequire(dnslineclientResolve(client, w, "example.test", kDsOnlyIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "resolve rejected");
    // SERVFAIL fails the only try.
    ares_dns_rec_type_t t0;
    uint16_t            id0 = sentQuery(0, &t0);
    respond(route_lines[0], id0, t0, ARES_RCODE_SERVFAIL, NULL);
    twfRequire(core_calls == 1 && core_cb != NULL && nmsgs == 0 && route_fins == 1, "fallback not started");

    dns_resolved_addr_t addrs[2] = {{.family = AF_INET6, .addrlen = sizeof(struct sockaddr_in6), .ttl = 5},
                                    {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in), .ttl = 500}};
    ((struct sockaddr_in6 *) &addrs[0].addr)->sin6_family = AF_INET6;
    ((struct sockaddr_in *) &addrs[1].addr)->sin_family   = AF_INET;
    core_cb(core_userdata, ARES_SUCCESS, NULL, addrs, 2);
    twfRequire(nmsgs == 1, "fallback result not deferred");
    pumpMessages();
    twfRequire(nresults == 1 && results[0].status == ARES_SUCCESS && results[0].naddrs == 1 &&
                   results[0].first.family == AF_INET && results[0].first.ttl == 60,
               "fallback result not filtered/clamped");
    recycleSent();
    dropWaiter(w);
    end();
}

static void testWorkerStopAndMessageCancel(void)
{
    begin("worker quiesce/stop closes in-flight lines and cancels waiters", baseConfig());
    line_t *w1 = newWaiter(), *w2 = newWaiter();
    lineRef(w1);
    twfRequire(dnslineclientResolve(client, w1, "example.test", kDsOnlyIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "resolve rejected");
    twfRequire(twfLineRefCount(w1) == 3, "waiter reference not held");
    line_t *l = route_lines[0];
    lineRef(l);

    dnslineclientWorkerQuiesce(client, 0);
    twfRequire(wloopNTimers(env.loop) == 0 && lineIsAlive(l), "quiesce must only stop timers");
    twfRequire(dnslineclientResolve(client, w2, "other.test", kDsOnlyIpV4, onResolved, host, NULL) == ARES_ECANCELLED,
               "admission open after quiesce");
    dnslineclientWorkerStop(client, 0);
    twfRequire(! lineIsAlive(l) && route_fins == 1 && nmsgs == 0 && nresults == 0, "stop did not close or cancel");
    twfRequire(twfLineRefCount(w1) == 2, "waiter reference leaked");
    dnslineclientWorkerStop(client, 0); // idempotent
    lineUnref(l);
    lineUnref(w1);
    dropWaiter(w1);
    dropWaiter(w2);
    recycleSent();
    end();

    begin("cancelled delivery message releases the waiter without a callback", baseConfig());
    w1 = newWaiter();
    lineRef(w1);
    twfRequire(dnslineclientResolve(client, w1, "example.test", kDsOnlyIpV4, onResolved, host, NULL) == ARES_SUCCESS,
               "resolve rejected");
    ares_dns_rec_type_t t0;
    uint16_t            id0 = sentQuery(0, &t0);
    respond(route_lines[0], id0, t0, ARES_RCODE_NOERROR, "203.0.113.1");
    twfRequire(nmsgs == 1 && twfLineRefCount(w1) == 3, "settled delivery shape");
    cancelMessages();
    twfRequire(nresults == 0 && twfLineRefCount(w1) == 2, "cancellation delivered or leaked");
    lineUnref(w1);
    dropWaiter(w1);
    recycleSent();
    end();
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure-random initialization failed");
    twfRequire(frandGlobalInit(), "fast-random global initialization failed");
    frandInit();
    testSuccessCoalesceCache();
    testTimeoutRotationAndFinish();
    testSynchronousFinish();
#if WW_HAVE_SPLICE
    testSpliceReply();
#endif
    testPauseNxdomain();
    testFallback();
    testWorkerStopAndMessageCancel();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
