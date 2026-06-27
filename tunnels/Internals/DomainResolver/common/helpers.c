#include "structure.h"

#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"

static int domainresolverSockTypeForLine(line_t *l)
{
    const routing_context_t *route = lineGetRoutingContext(l);
    const address_context_t *dest  = &route->dest_ctx;

    if (dest->proto_tcp && ! dest->proto_udp)
    {
        return SOCK_STREAM;
    }
    if (dest->proto_udp && ! dest->proto_tcp)
    {
        return SOCK_DGRAM;
    }
    if (route->network_type == WIO_TYPE_TCP)
    {
        return SOCK_STREAM;
    }
    if (route->network_type == WIO_TYPE_UDP)
    {
        return SOCK_DGRAM;
    }

    return 0;
}

static void domainresolverMovePending(buffer_queue_t *dest, buffer_queue_t *source)
{
    while (bufferqueueGetBufCount(source) > 0)
    {
        bufferqueuePushBack(dest, bufferqueuePopFront(source));
    }
}

static void domainresolverForwardInit(tunnel_t *t, line_t *l, domainresolver_direction_t direction)
{
    if (direction == kDomainResolverDirectionUpstream)
    {
        tunnelNextUpStreamInit(t, l);
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}

static void domainresolverForwardPayload(tunnel_t *t, line_t *l, domainresolver_direction_t direction, sbuf_t *buf)
{
    if (direction == kDomainResolverDirectionUpstream)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

static const char *domainresolverCopyDomainForLog(const address_context_t *dest_ctx, char domain[256])
{
    if (! addresscontextIsDomain(dest_ctx))
    {
        return "<unknown>";
    }

    stringCopyN(domain, dest_ctx->domain, 256);
    return domain;
}

static void domainresolverDrainPending(tunnel_t *t, line_t *l, domainresolver_direction_t direction,
                                       buffer_queue_t *pending)
{
    while (lineIsAlive(l) && bufferqueueGetBufCount(pending) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(pending);
        domainresolverForwardPayload(t, l, direction, buf);
    }

    bufferqueueDestroy(pending);
}

static void domainresolverLogResolved(const char *domain, const address_context_t *dest_ctx)
{
    if (! loggerCheckWriteLevel(getDnsLogger(), (log_level_e) LOG_LEVEL_DEBUG))
    {
        return;
    }

    sockaddr_u resolved_addr = addresscontextToSockAddr(dest_ctx);
    char       ip[SOCKADDR_STRLEN];
    loggerPrint(getDnsLogger(), LOG_LEVEL_DEBUG, "DomainResolver: %s resolved to %s", domain,
                SOCKADDR_STR(&resolved_addr, ip));
}

static enum domain_strategy domainresolverStrategyForLine(const domainresolver_tstate_t *ts,
                                                          const address_context_t *dest_ctx)
{
    return ts->use_line_strategy ? dest_ctx->domain_strategy : ts->strategy;
}

static void domainresolverOnDnsResolved(tunnel_t *t, line_t *l, void *userdata, int status, const char *error,
                                        const dns_resolved_addr_t *addrs, size_t naddrs)
{
    discard userdata;

    domainresolver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase != kDomainResolverPhaseResolving)
    {
        return;
    }

    domainresolver_tstate_t  *ts        = tunnelGetState(t);
    domainresolver_direction_t direction = ls->init_direction;
    address_context_t        *dest_ctx  = lineGetDestinationAddressContext(l);
    char                      domain_buf[256];
    const char               *domain    = domainresolverCopyDomainForLog(dest_ctx, domain_buf);

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "DomainResolver: async dns resolve failed for %s: %s", domain,
                    error != NULL ? error : ares_strerror(status));
        domainresolverCloseBeforeInit(t, l, direction);
        return;
    }

    const dns_resolved_addr_t *selected =
        dnsstrategySelectResolvedAddress(addrs, naddrs, domainresolverStrategyForLine(ts, dest_ctx));
    if (UNLIKELY(! dnsstrategyApplyResolvedAddress(dest_ctx, selected)))
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR,
                    "DomainResolver: async dns resolve returned no usable address for %s", domain);
        domainresolverCloseBeforeInit(t, l, direction);
        return;
    }

    buffer_queue_t pending_local = bufferqueueCreate(kDomainResolverPendingQueueInitialCapacity);
    domainresolverMovePending(&pending_local, &ls->pending);

    ls->phase          = kDomainResolverPhaseOpen;
    ls->init_direction = direction;

    domainresolverLogResolved(domain, dest_ctx);

    domainresolverForwardInit(t, l, direction);
    if (lineIsAlive(l))
    {
        domainresolverDrainPending(t, l, direction, &pending_local);
    }
    else
    {
        bufferqueueDestroy(&pending_local);
    }
}

bool domainresolverStartResolveIfNeeded(tunnel_t *t, line_t *l, domainresolver_lstate_t *ls,
                                        domainresolver_direction_t direction, bool *started_out)
{
    domainresolver_tstate_t *ts       = tunnelGetState(t);
    address_context_t      *dest_ctx = lineGetDestinationAddressContext(l);

    *started_out = false;

    if (addresscontextIsIpType(dest_ctx) || addresscontextIsDomainResolved(dest_ctx))
    {
        ls->phase          = kDomainResolverPhaseOpen;
        ls->init_direction = direction;
        return true;
    }

    if (ts->allow_missing_destination && ! addresscontextIsDomain(dest_ctx))
    {
        ls->phase          = kDomainResolverPhaseOpen;
        ls->init_direction = direction;
        return true;
    }

    if (UNLIKELY(! addresscontextIsDomain(dest_ctx)))
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "DomainResolver: destination address is not a resolvable domain");
        return false;
    }

    addresscontextSetDomainStrategy(dest_ctx, domainresolverStrategyForLine(ts, dest_ctx));

    const char *domain = dest_ctx->domain;
    int         socktype = domainresolverSockTypeForLine(l);

    if (ts->verbose)
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_DEBUG, "DomainResolver: resolving %s", domain);
    }

    ls->phase          = kDomainResolverPhaseResolving;
    ls->init_direction = direction;

    *started_out = true;
    int rc       = lineResolveDomainServiceAsync(l, domain, NULL, socktype, domainresolverOnDnsResolved, t, NULL);
    if (UNLIKELY(rc != ARES_SUCCESS))
    {
        *started_out       = false;
        ls->phase          = kDomainResolverPhaseIdle;
        ls->init_direction = kDomainResolverDirectionNone;
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "DomainResolver: failed to start async dns resolve for %s: %s",
                    domain, ares_strerror(rc));
        return false;
    }

    return true;
}

bool domainresolverQueueResolvingPayload(tunnel_t *t, line_t *l, domainresolver_lstate_t *ls, sbuf_t *buf,
                                         domainresolver_direction_t direction)
{
    if (ls->phase != kDomainResolverPhaseResolving || ls->init_direction != direction)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    /*
     * The byte limit is checked after enqueue so ownership stays simple: this
     * can exceed the limit by one buffer before the line is closed.
     */
    bufferqueuePushBack(&ls->pending, buf);
    if (bufferqueueGetBufLen(&ls->pending) <= kDomainResolverMaxPendingBytes)
    {
        return true;
    }

    loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "DomainResolver: pending payload queue overflow while resolving");
    domainresolverCloseBeforeInit(t, l, direction);
    return false;
}

void domainresolverCloseBeforeInit(tunnel_t *t, line_t *l, domainresolver_direction_t direction)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    lineLock(l);

    domainresolverLinestateDestroy(t, l, ls);

    if (direction == kDomainResolverDirectionUpstream && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    else if (direction == kDomainResolverDirectionDownstream && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}

void domainresolverCloseLine(tunnel_t *t, line_t *l, domainresolver_direction_t direction)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    bool was_open = ls->phase == kDomainResolverPhaseOpen;
    lineLock(l);

    domainresolverLinestateDestroy(t, l, ls);

    if (! was_open)
    {
        lineUnlock(l);
        return;
    }

    if (direction == kDomainResolverDirectionUpstream && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }
    else if (direction == kDomainResolverDirectionDownstream && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}
