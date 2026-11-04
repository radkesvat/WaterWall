#include "DnsLineClient/internal.h"

#include "loggers/dns_logger.h"

/*
 * Runtime of DnsLineClient.
 *
 * Every query lives on exactly one worker (its waiters' worker) and is listed
 * in that worker's in-flight inventory from creation until settlement. A query
 * runs at most one attempt at a time; an attempt owns one normal UDP line
 * (created here, destroyed only here) that carries one datagram per query type
 * (A and/or AAAA, distinct random ids). The attempt settles when every type
 * settled, when any type answered NXDOMAIN, or when its per-try timer expires:
 *
 *   any addresses            -> success (types that failed or timed out are ignored)
 *   NXDOMAIN                 -> ARES_ENOTFOUND (definitive, no rotation)
 *   every type NODATA        -> ARES_ENODATA (definitive, no rotation)
 *   otherwise                -> failed try: close the line, rotate to the next server
 *
 * After `tries` failed attempts the query either asks the worker c-ares channel
 * once (fallback-to-core) or fails every waiter with the last error.
 *
 * Waiter results are always delivered through a force-queued worker message on
 * the waiter's worker, never from dnslineclientResolve() itself. Queue
 * cancellation (quiescence/teardown) only releases the waiter's line reference.
 *
 * `refs` keeps the query object valid across re-entrant host callbacks: one
 * reference belongs to the inventory, one to each active driver frame, and one
 * to a pending c-ares fallback request.
 */

typedef struct dnslineclient_delivery_s
{
    line_t             *line;
    LineDnsResolveFn    cb;
    tunnel_t           *t;
    void               *userdata;
    int                 status;
    size_t              naddrs;
    dns_resolved_addr_t addrs[];
} dnslineclient_delivery_t;

static void dnslineclientQueryRun(dnslineclient_query_t *q);
static void dnslineclientAttemptFlush(dnslineclient_query_t *q);

uint8_t dnslineclientQmaskForStrategy(enum domain_strategy strategy)
{
    switch (strategy)
    {
    case kDsOnlyIpV4:
        return kDnsLineClientQtypeA;
    case kDsOnlyIpV6:
        return kDnsLineClientQtypeAAAA;
    default:
        return kDnsLineClientQtypeA | kDnsLineClientQtypeAAAA;
    }
}

static inline dnslineclient_worker_t *dnslineclientGetWorker(dnslineclient_t *client, wid_t wid)
{
    assert(wid < client->workers_count);
    return &client->workers[wid];
}

/* ------------------------------------------------------------------------ */
/* waiter delivery                                                          */
/* ------------------------------------------------------------------------ */

static void dnslineclientDeliveryRun(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    dnslineclient_delivery_t *d = arg1;
    if (lineIsAlive(d->line))
    {
        d->cb(d->t, d->line, d->userdata, d->status, NULL, d->naddrs > 0 ? d->addrs : NULL, d->naddrs);
    }
    lineUnref(d->line);
    memoryFree(d);
}

/* Notification only: may run on a teardown thread; touches nothing but the record and its line reference. */
static void dnslineclientDeliveryCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard arg2;
    discard arg3;
    discard reason;

    dnslineclient_delivery_t *d = arg1;
    lineUnref(d->line);
    memoryFree(d);
}

/* Consumes `waiter` and its line reference. Returns false when the result will never be delivered. */
static bool dnslineclientDeliver(wid_t wid, dnslineclient_waiter_t *waiter, int status,
                                 const dns_resolved_addr_t *addrs, size_t naddrs)
{
    if (status == ARES_ECANCELLED)
    {
        lineUnref(waiter->line);
        memoryFree(waiter);
        return false;
    }

    dnslineclient_delivery_t *d = memoryAllocate(sizeof(*d) + naddrs * sizeof(dns_resolved_addr_t));
    d->line                     = waiter->line;
    d->cb                       = waiter->cb;
    d->t                        = waiter->t;
    d->userdata                 = waiter->userdata;
    d->status                   = status;
    d->naddrs                   = naddrs;
    if (naddrs > 0)
    {
        memoryCopy(d->addrs, addrs, naddrs * sizeof(dns_resolved_addr_t));
    }
    memoryFree(waiter);

    worker_message_submit_result_e result = sendWorkerMessageForceQueueWithCleanup(
        wid, dnslineclientDeliveryRun, dnslineclientDeliveryCleanup, d, NULL, NULL);
    if (result == kWorkerMessageSubmitAccepted)
    {
        return true;
    }
    if (result == kWorkerMessageSubmitRejectedCallerRetains)
    {
        dnslineclientDeliveryCleanup(d, NULL, NULL, kWorkerMessageCancelAdmissionClosed);
    }
    return false;
}

/* ------------------------------------------------------------------------ */
/* query lifetime                                                           */
/* ------------------------------------------------------------------------ */

static void dnslineclientSlotsClear(dnslineclient_query_t *q)
{
    for (uint32_t i = 0; i < q->nslots; ++i)
    {
        dnslineclient_slot_t *slot = &q->slots[i];
        if (slot->pending != NULL)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(q->wid), slot->pending);
        }
        memoryFree(slot->addrs);
        memoryZero(slot, sizeof(*slot));
    }
    q->nslots = 0;
}

static inline void dnslineclientQueryHold(dnslineclient_query_t *q)
{
    ++q->refs;
}

static void dnslineclientQueryRelease(dnslineclient_query_t *q)
{
    assert(q->refs > 0);
    if (--q->refs != 0)
    {
        return;
    }
    assert(q->phase == kDnsLineClientPhaseDone && q->line == NULL && q->timer == NULL && q->waiters == NULL &&
           ! q->in_inventory);
    dnslineclientSlotsClear(q);
    memoryFree(q);
}

static void dnslineclientInventoryRemove(dnslineclient_query_t *q)
{
    if (! q->in_inventory)
    {
        return;
    }
    dnslineclient_worker_t *w = q->worker;
    if (q->prev != NULL)
    {
        q->prev->next = q->next;
    }
    else
    {
        w->inflight = q->next;
    }
    if (q->next != NULL)
    {
        q->next->prev = q->prev;
    }
    q->prev = q->next = NULL;
    q->in_inventory   = false;
    --w->inflight_count;
}

static void dnslineclientTimerStop(dnslineclient_query_t *q)
{
    wtimer_t *timer = q->timer;
    if (timer == NULL)
    {
        return;
    }
    q->timer = NULL;
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
}

/*
 * The single, idempotent close path of an attempt line. The line leaves the
 * query (its inventory slot) before any neighbour callback. `finish_upstream`
 * is false when the route already finished the line toward us.
 */
static void dnslineclientAttemptClose(dnslineclient_query_t *q, bool finish_upstream)
{
    dnslineclientTimerStop(q);

    line_t *l = q->line;
    if (l == NULL)
    {
        return;
    }
    q->line = NULL;

    for (uint32_t i = 0; i < q->nslots; ++i)
    {
        if (q->slots[i].pending != NULL)
        {
            lineReuseBuffer(l, q->slots[i].pending);
            q->slots[i].pending = NULL;
        }
    }

    dnslineclient_t *c        = q->client;
    bool             send_fin = finish_upstream && q->upstream_open;
    q->upstream_open          = false;
    q->paused                 = false;

    c->detach(c->host, l);
    if (send_fin)
    {
        tunnelNextUpStreamFinish(c->host, l);
    }
    lineDestroy(l);
}

/* Settle the whole query exactly once: leave the inventory, close the line, deliver every waiter. */
static void dnslineclientQuerySettle(dnslineclient_query_t *q, int status, const dns_resolved_addr_t *addrs,
                                     size_t naddrs)
{
    if (q->phase == kDnsLineClientPhaseDone)
    {
        return;
    }
    q->phase = kDnsLineClientPhaseDone;

    bool inventory_ref = q->in_inventory;
    dnslineclientInventoryRemove(q);
    dnslineclientAttemptClose(q, true);

    if (status != ARES_SUCCESS && status != ARES_ECANCELLED)
    {
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_DEBUG,
                    "DnsLineClient: resolving %s failed: %s",
                    q->domain,
                    ares_strerror(status));
    }

    dnslineclient_waiter_t *waiter = q->waiters;
    q->waiters                     = NULL;
    q->waiters_tail                = &q->waiters;
    while (waiter != NULL)
    {
        dnslineclient_waiter_t *next = waiter->next;
        discard                 dnslineclientDeliver(q->wid, waiter, status, addrs, naddrs);
        waiter = next;
    }

    if (inventory_ref)
    {
        dnslineclientQueryRelease(q);
    }
}

/* ------------------------------------------------------------------------ */
/* core fallback                                                            */
/* ------------------------------------------------------------------------ */

static uint32_t dnslineclientClampTtl(const dnslineclient_config_t *cfg, uint32_t ttl)
{
    return min(max(ttl, cfg->min_ttl), cfg->max_ttl);
}

static void dnslineclientOnCoreResolved(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                                        size_t naddrs)
{
    discard                error;
    dnslineclient_query_t *q = userdata;

    if (q->phase == kDnsLineClientPhaseCore)
    {
        if (asyncdnsStatusIsShutdown(status))
        {
            dnslineclientQuerySettle(q, ARES_ECANCELLED, NULL, 0);
        }
        else if (status != ARES_SUCCESS)
        {
            dnslineclientQuerySettle(q, status, NULL, 0);
        }
        else
        {
            // Keep only the families this query asked for, so cache entries match their key.
            dns_resolved_addr_t *kept  = naddrs > 0 ? memoryAllocate(naddrs * sizeof(*kept)) : NULL;
            size_t               nkept = 0;
            uint32_t             ttl   = UINT32_MAX;
            for (size_t i = 0; i < naddrs; ++i)
            {
                bool want = (addrs[i].family == AF_INET && (q->qmask & kDnsLineClientQtypeA) != 0) ||
                            (addrs[i].family == AF_INET6 && (q->qmask & kDnsLineClientQtypeAAAA) != 0);
                if (! want)
                {
                    continue;
                }
                kept[nkept] = addrs[i];
                ttl         = min(ttl, (uint32_t) max(addrs[i].ttl, 0));
                ++nkept;
            }
            if (nkept > 0)
            {
                ttl = dnslineclientClampTtl(&q->client->cfg, ttl);
                for (size_t i = 0; i < nkept; ++i)
                {
                    kept[i].ttl = (int) ttl;
                }
                dnslineclientCacheInsert(&q->worker->cache,
                                         q->domain,
                                         q->qmask,
                                         kept,
                                         nkept,
                                         ttl,
                                         wloopNowMonotonicMS(getWorkerLoop(q->wid)));
                dnslineclientQuerySettle(q, ARES_SUCCESS, kept, nkept);
            }
            else
            {
                dnslineclientQuerySettle(q, ARES_ENODATA, NULL, 0);
            }
            memoryFree(kept);
        }
    }

    dnslineclientQueryRelease(q); // the fallback request's reference
}

static void dnslineclientQueryExhausted(dnslineclient_query_t *q)
{
    dnslineclient_t *c      = q->client;
    int              status = q->last_status != ARES_SUCCESS ? q->last_status : ARES_ETIMEOUT;

    if (! c->cfg.fallback_to_core || q->worker->closed)
    {
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_WARN,
                    "DnsLineClient: all %u chain attempts for %s failed: %s",
                    (unsigned) q->attempts,
                    q->domain,
                    ares_strerror(status));
        dnslineclientQuerySettle(q, status, NULL, 0);
        return;
    }

    loggerPrint(getDnsLogger(),
                LOG_LEVEL_WARN,
                "DnsLineClient: all %u chain attempts for %s failed (%s); falling back to the core resolver",
                (unsigned) q->attempts,
                q->domain,
                ares_strerror(status));

    q->phase = kDnsLineClientPhaseCore;
    dnslineclientQueryHold(q);
    // The callback can run synchronously (hosts file); it settles and releases the hold itself.
    int rc = workerResolveDomainServiceAsync(q->wid, q->domain, NULL, 0, dnslineclientOnCoreResolved, q);
    if (rc != ARES_SUCCESS)
    {
        dnslineclientQuerySettle(q, asyncdnsStatusIsShutdown(rc) ? ARES_ECANCELLED : rc, NULL, 0);
        dnslineclientQueryRelease(q);
    }
}

/* ------------------------------------------------------------------------ */
/* attempts                                                                 */
/* ------------------------------------------------------------------------ */

static void dnslineclientAttemptFail(dnslineclient_query_t *q, int status)
{
    q->last_status = status;
    // Later queries on this worker start at the next server instead of waiting on this one again.
    if (q->worker->preferred_server == q->server_idx)
    {
        q->worker->preferred_server = (q->server_idx + 1U) % q->client->cfg.servers_count;
    }
    loggerPrint(getDnsLogger(),
                LOG_LEVEL_DEBUG,
                "DnsLineClient: attempt %u for %s failed: %s",
                (unsigned) q->attempts,
                q->domain,
                ares_strerror(status));
    dnslineclientAttemptClose(q, true);
    dnslineclientQueryRun(q);
}

/* Decide the attempt once enough slots settled. `timed_out` settles every outstanding slot as a timeout. */
static void dnslineclientAttemptEvaluate(dnslineclient_query_t *q, bool timed_out)
{
    bool   nxdomain    = false;
    bool   all_settled = true;
    size_t total       = 0;

    for (uint32_t i = 0; i < q->nslots; ++i)
    {
        dnslineclient_slot_t *slot = &q->slots[i];
        if (! slot->settled && timed_out)
        {
            slot->settled = true;
            slot->status  = ARES_ETIMEOUT;
        }
        all_settled = all_settled && slot->settled;
        nxdomain    = nxdomain || (slot->settled && slot->status == ARES_ENOTFOUND);
        total += slot->status == ARES_SUCCESS && slot->settled ? slot->naddrs : 0;
    }

    if (! all_settled && ! nxdomain)
    {
        return;
    }

    if (total > 0 && all_settled)
    {
        // Slot order is A then AAAA, so the merged answer lists IPv4 first.
        dns_resolved_addr_t *merged = memoryAllocate(total * sizeof(*merged));
        size_t               used   = 0;
        uint32_t             ttl    = UINT32_MAX;
        for (uint32_t i = 0; i < q->nslots; ++i)
        {
            dnslineclient_slot_t *slot = &q->slots[i];
            if (slot->status != ARES_SUCCESS || slot->naddrs == 0)
            {
                continue;
            }
            memoryCopy(&merged[used], slot->addrs, slot->naddrs * sizeof(*merged));
            used += slot->naddrs;
            ttl = min(ttl, slot->ttl);
        }
        for (size_t i = 0; i < used; ++i)
        {
            merged[i].ttl = (int) ttl;
        }
        // A type that timed out or failed may still have addresses: keep such a partial answer only for min-ttl.
        uint32_t cache_ttl = ttl;
        for (uint32_t i = 0; i < q->nslots; ++i)
        {
            const int st = q->slots[i].status;
            if (st != ARES_SUCCESS && st != ARES_ENODATA)
            {
                cache_ttl = min(cache_ttl, q->client->cfg.min_ttl);
            }
        }
        q->worker->preferred_server = q->server_idx;
        dnslineclientCacheInsert(&q->worker->cache,
                                 q->domain,
                                 q->qmask,
                                 merged,
                                 used,
                                 cache_ttl,
                                 wloopNowMonotonicMS(getWorkerLoop(q->wid)));
        dnslineclientQuerySettle(q, ARES_SUCCESS, merged, used);
        memoryFree(merged);
        return;
    }

    if (nxdomain && total == 0)
    {
        dnslineclientQuerySettle(q, ARES_ENOTFOUND, NULL, 0);
        return;
    }
    if (! all_settled)
    {
        return; // NXDOMAIN on one type while another already holds addresses: wait for the rest
    }

    int failure = ARES_ENODATA;
    for (uint32_t i = 0; i < q->nslots; ++i)
    {
        if (q->slots[i].status != ARES_ENODATA && q->slots[i].status != ARES_SUCCESS)
        {
            failure = q->slots[i].status;
            break;
        }
    }
    if (failure == ARES_ENODATA)
    {
        dnslineclientQuerySettle(q, ARES_ENODATA, NULL, 0);
        return;
    }
    dnslineclientAttemptFail(q, failure);
}

static void dnslineclientOnTimeout(wtimer_t *timer)
{
    dnslineclient_query_t *q = weventGetUserdata(timer);
    if (q == NULL)
    {
        return;
    }
    // A due one-shot is reclaimed by the dispatcher; only forget it.
    assert(q->timer == timer);
    q->timer = NULL;

    dnslineclientQueryHold(q);
    dnslineclientAttemptEvaluate(q, true);
    dnslineclientQueryRelease(q);
}

static uint16_t dnslineclientNewId(const dnslineclient_query_t *q)
{
    for (;;)
    {
        uint16_t id    = (uint16_t) (fastRand32() & 0xFFFFU);
        bool     taken = false;
        for (uint32_t i = 0; i < q->nslots; ++i)
        {
            taken = taken || q->slots[i].id == id;
        }
        if (! taken)
        {
            return id;
        }
    }
}

static bool dnslineclientPrepareSlots(dnslineclient_query_t *q)
{
    static const ares_dns_rec_type_t kTypes[kDnsLineClientMaxSlots] = {ARES_REC_TYPE_A, ARES_REC_TYPE_AAAA};
    static const uint8_t             kMasks[kDnsLineClientMaxSlots] = {kDnsLineClientQtypeA, kDnsLineClientQtypeAAAA};

    dnslineclientSlotsClear(q);
    for (uint32_t i = 0; i < kDnsLineClientMaxSlots; ++i)
    {
        if ((q->qmask & kMasks[i]) == 0)
        {
            continue;
        }
        dnslineclient_slot_t *slot = &q->slots[q->nslots];
        slot->id                   = dnslineclientNewId(q);
        slot->qtype                = kTypes[i];
        ++q->nslots;

        unsigned char *wire = NULL;
        size_t         len  = 0;
        int            rc   = dnslineclientCodecBuildQuery(q->domain, slot->id, slot->qtype, &wire, &len);
        if (rc != ARES_SUCCESS)
        {
            q->last_status = rc;
            return false;
        }
        sbuf_t *buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(q->wid));
        sbufSetLength(buf, 0);
        buf = sbufReserveSpace(buf, (uint32_t) len);
        sbufSetLength(buf, (uint32_t) len);
        sbufWrite(buf, wire, (uint32_t) len);
        ares_free_string(wire);
        slot->pending = buf;
    }
    return q->nslots > 0;
}

static void dnslineclientAttemptStart(dnslineclient_query_t *q)
{
    dnslineclient_t              *c      = q->client;
    q->server_idx                        = (q->server_base + q->attempts) % c->cfg.servers_count;
    const dnslineclient_server_t *server = &c->cfg.servers[q->server_idx];
    ++q->attempts;

    if (! dnslineclientPrepareSlots(q))
    {
        dnslineclientQuerySettle(q, q->last_status != ARES_SUCCESS ? q->last_status : ARES_EBADNAME, NULL, 0);
        return;
    }

    // Arm first: a refusal means the loop closed admission, so no line is created.
    wtimer_t *timer = wtimerAdd(getWorkerLoop(q->wid), dnslineclientOnTimeout, c->cfg.timeout_ms, 1);
    if (timer == NULL)
    {
        dnslineclientQuerySettle(q, ARES_ECANCELLED, NULL, 0);
        return;
    }
    weventSetUserData(timer, q);
    q->timer = timer;

    line_t            *l    = lineCreate(tunnelchainGetLinePools(tunnelGetChain(c->host)), q->wid);
    address_context_t *dest = lineGetDestinationAddressContext(l);
    addresscontextSetIpPortProtocol(dest, &server->ip, server->port, IP_PROTO_UDP);
    // Endpoint setters reset optional flags, so the resolver-origin mark goes last.
    addresscontextSetResolverOrigin(dest, true);

    // Publish into the inventory (the query) before any callback can observe the line.
    q->line          = l;
    q->upstream_open = true;
    q->paused        = false;

    lineRef(l);
    c->open(c->host, l, q);
    bool alive = lineIsAlive(l);
    lineUnref(l);
    if (! alive || q->line != l)
    {
        return;
    }
    dnslineclientAttemptFlush(q);
}

/* Send queued query datagrams until done, paused, or the attempt closed. */
static void dnslineclientAttemptFlush(dnslineclient_query_t *q)
{
    line_t *l = q->line;
    if (l == NULL)
    {
        return;
    }

    dnslineclientQueryHold(q);
    for (uint32_t i = 0; i < q->nslots; ++i)
    {
        if (q->line != l || q->paused)
        {
            break;
        }
        sbuf_t *buf = q->slots[i].pending;
        if (buf == NULL)
        {
            continue;
        }
        q->slots[i].pending = NULL;

        lineRef(l);
        tunnelNextUpStreamPayload(q->client->host, l, buf);
        bool alive = lineIsAlive(l);
        lineUnref(l);
        if (! alive)
        {
            break;
        }
    }
    dnslineclientQueryRelease(q);
}

/* Drive the attempt sequence iteratively; nested failures only request another pass. */
static void dnslineclientQueryRun(dnslineclient_query_t *q)
{
    if (q->running)
    {
        q->kick = true;
        return;
    }

    q->running = true;
    dnslineclientQueryHold(q);
    do
    {
        q->kick = false;
        if (q->phase != kDnsLineClientPhaseChain || q->line != NULL)
        {
            break;
        }
        if (q->worker->closed)
        {
            dnslineclientQuerySettle(q, ARES_ECANCELLED, NULL, 0);
            break;
        }
        if (q->attempts >= q->client->cfg.tries)
        {
            dnslineclientQueryExhausted(q);
            break;
        }
        dnslineclientAttemptStart(q);
    } while (q->kick);
    q->running = false;
    dnslineclientQueryRelease(q);
}

/* ------------------------------------------------------------------------ */
/* host-forwarded line events                                               */
/* ------------------------------------------------------------------------ */

void dnslineclientOnLineEst(dnslineclient_query_t *query, line_t *l)
{
    // UDP readiness carries no information for a single request/response exchange.
    discard query;
    discard l;
}

void dnslineclientOnLinePayload(dnslineclient_query_t *q, line_t *l, sbuf_t *buf)
{
    if (q->line != l || q->phase != kDnsLineClientPhaseChain)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    // A stream carrier (VlessClient, TrojanClient, ...) can return a datagram whose
    // bytes still sit in a kernel pipe. Copy it into memory before parsing; an
    // oversized one is dropped first, since the codec would ignore it anyway.
    if (sbufIsSplice(buf))
    {
        if (sbufGetLength(buf) > kDnsLineClientMaxResponseBytes)
        {
            lineReuseBuffer(l, buf);
            loggerPrint(getDnsLogger(), LOG_LEVEL_DEBUG, "DnsLineClient: ignored a stray datagram for %s", q->domain);
            return;
        }
        buf = sbufEnsureOrdinary(lineGetBufferPool(l), buf);
    }

    uint16_t            ids[kDnsLineClientMaxSlots];
    ares_dns_rec_type_t qtypes[kDnsLineClientMaxSlots];
    uint32_t            map[kDnsLineClientMaxSlots];
    uint32_t            n = 0;
    for (uint32_t i = 0; i < q->nslots; ++i)
    {
        if (! q->slots[i].settled)
        {
            ids[n]    = q->slots[i].id;
            qtypes[n] = q->slots[i].qtype;
            map[n]    = i;
            ++n;
        }
    }

    dnslineclient_answer_t       answer;
    dnslineclient_parse_result_e result = dnslineclientCodecParseResponse(sbufGetRawPtr(buf),
                                                                          sbufGetLength(buf),
                                                                          q->domain,
                                                                          ids,
                                                                          qtypes,
                                                                          n,
                                                                          q->client->cfg.min_ttl,
                                                                          q->client->cfg.max_ttl,
                                                                          &answer);
    lineReuseBuffer(l, buf);

    if (result == kDnsLineClientParseIgnored)
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_DEBUG, "DnsLineClient: ignored a stray datagram for %s", q->domain);
        return;
    }

    dnslineclient_slot_t *slot = &q->slots[map[answer.slot]];
    slot->settled              = true;
    slot->status               = answer.status;
    slot->ttl                  = answer.ttl;
    slot->naddrs               = answer.naddrs;
    slot->addrs                = answer.addrs;

    dnslineclientQueryHold(q);
    dnslineclientAttemptEvaluate(q, false);
    dnslineclientQueryRelease(q);
}

void dnslineclientOnLineFinish(dnslineclient_query_t *q, line_t *l)
{
    if (UNLIKELY(q->line != l))
    {
        LOGF("DnsLineClient: Finish for a line that is not the current attempt line");
        abortProgramNow(1);
    }
    // The route closed toward us: never answer upstream; the line must be dead on return.
    q->upstream_open = false;
    dnslineclientQueryHold(q);
    dnslineclientAttemptClose(q, false);
    if (q->phase == kDnsLineClientPhaseChain)
    {
        q->last_status = ARES_ECONNREFUSED;
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_DEBUG,
                    "DnsLineClient: route finished attempt %u for %s before an answer",
                    (unsigned) q->attempts,
                    q->domain);
        dnslineclientQueryRun(q);
    }
    dnslineclientQueryRelease(q);
}

void dnslineclientOnLinePause(dnslineclient_query_t *q, line_t *l)
{
    if (q->line == l)
    {
        q->paused = true;
    }
}

void dnslineclientOnLineResume(dnslineclient_query_t *q, line_t *l)
{
    if (q->line == l)
    {
        q->paused = false;
        dnslineclientAttemptFlush(q);
    }
}

/* ------------------------------------------------------------------------ */
/* public API                                                               */
/* ------------------------------------------------------------------------ */

dnslineclient_t *dnslineclientCreate(const dnslineclient_config_t *cfg, tunnel_t *host, dnslineclient_open_fn open,
                                     dnslineclient_detach_fn detach)
{
    assert(cfg != NULL && host != NULL && open != NULL && detach != NULL);
    assert(cfg->servers_count > 0 && cfg->servers_count <= kDnsLineClientMaxServers && cfg->tries > 0);

    wid_t            count  = getWorkersCount();
    dnslineclient_t *client = memoryAllocateZero(sizeof(*client) + (size_t) count * sizeof(dnslineclient_worker_t));
    client->cfg             = *cfg;
    client->host            = host;
    client->open            = open;
    client->detach          = detach;
    client->workers_count   = count;
    for (wid_t i = 0; i < count; ++i)
    {
        dnslineclientCacheInit(&client->workers[i].cache, cfg->cache_size);
    }
    return client;
}

void dnslineclientDestroy(dnslineclient_t *client)
{
    if (client == NULL)
    {
        return;
    }
    for (wid_t i = 0; i < client->workers_count; ++i)
    {
        dnslineclient_worker_t *w = &client->workers[i];
        if (UNLIKELY(w->inflight != NULL))
        {
            LOGF("DnsLineClient: destroyed with in-flight queries on worker %u; worker stop did not run", (unsigned) i);
            abortProgramNow(1);
        }
        dnslineclientCacheDestroy(&w->cache);
    }
    memoryFree(client);
}

void dnslineclientWorkerQuiesce(dnslineclient_t *client, wid_t wid)
{
    dnslineclient_worker_t *w = dnslineclientGetWorker(client, wid);
    w->closed                 = true;
    for (dnslineclient_query_t *q = w->inflight; q != NULL; q = q->next)
    {
        dnslineclientTimerStop(q);
    }
}

void dnslineclientWorkerStop(dnslineclient_t *client, wid_t wid)
{
    dnslineclient_worker_t *w = dnslineclientGetWorker(client, wid);
    w->closed                 = true;
    while (w->inflight != NULL)
    {
        dnslineclient_query_t *q = w->inflight;
        dnslineclientQueryHold(q);
        dnslineclientQuerySettle(q, ARES_ECANCELLED, NULL, 0);
        dnslineclientQueryRelease(q);
    }
    dnslineclientCacheDestroy(&w->cache);
}

dnslineclient_query_t *dnslineclientFindInflight(dnslineclient_t *client, wid_t wid, const char *domain, uint8_t qmask)
{
    for (dnslineclient_query_t *q = dnslineclientGetWorker(client, wid)->inflight; q != NULL; q = q->next)
    {
        if (q->qmask == qmask && q->phase != kDnsLineClientPhaseDone && stringCompare(q->domain, domain) == 0)
        {
            return q;
        }
    }
    return NULL;
}

int dnslineclientResolve(dnslineclient_t *client, line_t *waiter, const char *domain, enum domain_strategy strategy,
                         LineDnsResolveFn cb, tunnel_t *t, void *userdata)
{
    assert(client != NULL && waiter != NULL && domain != NULL && cb != NULL);
    assert(lineIsOnCurrentWorker(waiter));

    const wid_t             wid  = lineGetWID(waiter);
    dnslineclient_worker_t *w    = dnslineclientGetWorker(client, wid);
    wloop_t                *loop = getWorkerLoop(wid);
    if (w->closed || ! wloopNormalDispatchAllowed(loop))
    {
        return ARES_ECANCELLED;
    }

    char name[kDnsLineClientMaxDomainLength + 1];
    if (! dnslineclientNormalizeDomain(domain, name))
    {
        return ARES_EBADNAME;
    }
    const uint8_t qmask = dnslineclientQmaskForStrategy(strategy);

    // Each in-flight query has a waiting line, but many distinct names would make every lookup scan a long list.
    if (w->inflight_count >= kDnsLineClientMaxInflightPerWorker &&
        dnslineclientFindInflight(client, wid, name, qmask) == NULL)
    {
        return ARES_EREFUSED;
    }

    dnslineclient_waiter_t *rec = memoryAllocate(sizeof(*rec));
    *rec = (dnslineclient_waiter_t){.next = NULL, .line = waiter, .cb = cb, .t = t, .userdata = userdata};
    lineRef(waiter);

    const dnslineclient_cache_entry_t *hit =
        dnslineclientCacheLookup(&w->cache, name, qmask, wloopNowMonotonicMS(loop));
    if (hit != NULL)
    {
        return dnslineclientDeliver(wid, rec, ARES_SUCCESS, hit->addrs, hit->naddrs) ? ARES_SUCCESS : ARES_ECANCELLED;
    }

    dnslineclient_query_t *q = dnslineclientFindInflight(client, wid, name, qmask);
    if (q != NULL)
    {
        *q->waiters_tail = rec;
        q->waiters_tail  = &rec->next;
        return ARES_SUCCESS;
    }

    q               = memoryAllocateZero(sizeof(*q));
    q->client       = client;
    q->worker       = w;
    q->wid          = wid;
    q->qmask        = qmask;
    q->phase        = kDnsLineClientPhaseChain;
    q->refs         = 1; // inventory
    q->waiters      = rec;
    q->waiters_tail = &rec->next;
    q->server_base  = w->preferred_server;
    memoryCopy(q->domain, name, stringLength(name) + 1);

    q->in_inventory = true;
    q->next         = w->inflight;
    if (w->inflight != NULL)
    {
        w->inflight->prev = q;
    }
    w->inflight = q;
    ++w->inflight_count;

    dnslineclientQueryRun(q);
    return ARES_SUCCESS;
}
