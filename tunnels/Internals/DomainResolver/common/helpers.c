#include "structure.h"

#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"

static const char *domainresolverCopyDomainForLog(const address_context_t *dest_ctx, char domain[256])
{
    if (! addresscontextIsDomain(dest_ctx))
    {
        return "<unknown>";
    }

    stringCopyN(domain, dest_ctx->domain, 256);
    return domain;
}

bool domainresolverUpdateSourcePressure(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls     = lineGetState(l, t);
    const bool               paused = ls->pending_source_hold || ls->next_paused;
    if (ls->source_paused == paused)
        return true;
    // Ownership, received permission and emitted state are all authoritative
    // before a source callback can admit nested input or finish the line.
    ls->source_paused = paused;
    return lineCallWithRef(l, paused ? tunnelPrevDownStreamPause : tunnelPrevDownStreamResume, t);
}

bool domainresolverDrainPending(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase != kDomainResolverPhaseOpen || ls->init_dispatching || ls->draining)
        return true;
    lineRef(l);
    ls->draining = true;
    while (lineIsAlive(l) && ! ls->next_paused && bufferqueueGetBufCount(&ls->pending) != 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending);
        tunnelNextUpStreamPayload(t, l, buf);
    }
    bool alive = lineIsAlive(l);
    if (alive)
    {
        ls->draining = false;
        if (bufferqueueGetBufCount(&ls->pending) == 0)
            ls->pending_source_hold = false;
        alive = domainresolverUpdateSourcePressure(t, l);
    }
    lineUnref(l);
    return alive;
}

void domainresolverOpenPath(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    lineRef(l);
    ls->phase            = kDomainResolverPhaseOpen;
    ls->init_dispatching = true;
    tunnelNextUpStreamInit(t, l);
    if (lineIsAlive(l))
    {
        ls->init_dispatching = false;
        if (ls->prev_paused && ! ls->read_pause_sent)
        {
            ls->read_pause_sent = true;
            tunnelNextUpStreamPause(t, l);
        }
        if (lineIsAlive(l))
            discard domainresolverDrainPending(t, l);
    }
    lineUnref(l);
}

static void domainresolverLogResolved(const char *domain, const address_context_t *dest_ctx)
{
    if (! loggerCheckWriteLevel(getDnsLogger(), (log_level_e) LOG_LEVEL_DEBUG))
    {
        return;
    }

    sockaddr_u resolved_addr = addresscontextToSockAddr(dest_ctx);
    char       ip[SOCKADDR_STRLEN];
    loggerPrint(
        getDnsLogger(), LOG_LEVEL_DEBUG, "DomainResolver: %s resolved to %s", domain, SOCKADDR_STR(&resolved_addr, ip));
}

static enum domain_strategy domainresolverStrategyForLine(const domainresolver_tstate_t *ts,
                                                          const address_context_t       *dest_ctx)
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

    domainresolver_tstate_t   *ts        = tunnelGetState(t);
    address_context_t         *dest_ctx  = lineGetDestinationAddressContext(l);
    char                       domain_buf[256];
    const char                *domain = domainresolverCopyDomainForLog(dest_ctx, domain_buf);

    if (status != ARES_SUCCESS || naddrs == 0)
    {
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "DomainResolver: async dns resolve failed for %s: %s",
                    domain,
                    error != NULL ? error : ares_strerror(status));
        domainresolverCloseLine(t, l);
        return;
    }

    const dns_resolved_addr_t *selected =
        dnsstrategySelectResolvedAddress(addrs, naddrs, domainresolverStrategyForLine(ts, dest_ctx));
    if (UNLIKELY(! dnsstrategyApplyResolvedAddress(dest_ctx, selected)))
    {
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "DomainResolver: async dns resolve returned no usable address for %s",
                    domain);
        domainresolverCloseLine(t, l);
        return;
    }

    domainresolverLogResolved(domain, dest_ctx);
    domainresolverOpenPath(t, l);
}

bool domainresolverStartResolveIfNeeded(tunnel_t *t, line_t *l, domainresolver_lstate_t *ls, bool *started_out)
{
    domainresolver_tstate_t *ts       = tunnelGetState(t);
    address_context_t       *dest_ctx = lineGetDestinationAddressContext(l);

    *started_out = false;

    if (addresscontextIsIpType(dest_ctx) || addresscontextIsDomainResolved(dest_ctx))
    {
        ls->phase = kDomainResolverPhaseOpen;
        return true;
    }

    if (ts->allow_missing_destination && ! addresscontextIsDomain(dest_ctx))
    {
        ls->phase = kDomainResolverPhaseOpen;
        return true;
    }

    if (UNLIKELY(! addresscontextIsDomain(dest_ctx)))
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "DomainResolver: destination address is not a resolvable domain");
        return false;
    }

    addresscontextSetDomainStrategy(dest_ctx, domainresolverStrategyForLine(ts, dest_ctx));

    const char *domain   = dest_ctx->domain;
    int         socktype = addresscontextGetSockType(dest_ctx);

    if (ts->verbose)
    {
        loggerPrint(getDnsLogger(), LOG_LEVEL_DEBUG, "DomainResolver: resolving %s", domain);
    }

    ls->phase = kDomainResolverPhaseResolving;

    *started_out = true;
    int rc       = lineResolveDomainServiceAsync(l, domain, NULL, socktype, domainresolverOnDnsResolved, t, NULL);
    if (UNLIKELY(rc != ARES_SUCCESS))
    {
        *started_out = false;
        ls->phase    = kDomainResolverPhaseIdle;
        loggerPrint(getDnsLogger(),
                    LOG_LEVEL_ERROR,
                    "DomainResolver: failed to start async dns resolve for %s: %s",
                    domain,
                    ares_strerror(rc));
        return false;
    }

    return true;
}

bool domainresolverQueuePayload(tunnel_t *t, line_t *l, domainresolver_lstate_t *ls, sbuf_t *buf)
{
    if (LIKELY(bufferqueueTryPushBack(&ls->pending, &buf)))
    {
        ls->pending_source_hold = true;
        return domainresolverUpdateSourcePressure(t, l);
    }
    lineReuseBuffer(l, buf);
    loggerPrint(getDnsLogger(), LOG_LEVEL_ERROR, "DomainResolver: pending payload retention overflow");
    domainresolverCloseLine(t, l);
    return false;
}

/* Internal failure closes only initialized neighbours. The normal line creator
 * is reached through prev; this borrowed line is never destroyed here. */
void domainresolverCloseLine(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    bool                     was_open = ls->phase == kDomainResolverPhaseOpen;
    lineRef(l);
    domainresolverLinestateDestroy(t, l, ls);
    if (was_open && lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnref(l);
}
