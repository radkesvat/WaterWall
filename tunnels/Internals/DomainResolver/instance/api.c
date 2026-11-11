#include "structure.h"

#include "DomainResolver/interface.h"
#include "loggers/network_logger.h"

api_result_t domainresolverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}

void domainresolverTunnelUseLineStrategy(tunnel_t *t, bool enabled)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);
    ts->use_line_strategy       = enabled;
}

void domainresolverTunnelAllowMissingDestination(tunnel_t *t, bool enabled)
{
    domainresolver_tstate_t *ts   = tunnelGetState(t);
    ts->allow_missing_destination = enabled;
}

void domainresolverTunnelSetPrepareHook(tunnel_t *t, tunnel_t *owner, uint32_t user_lstate_size,
                                        domainresolver_prepare_fn             prepare,
                                        domainresolver_user_lstate_destroy_fn destroy)
{
    if (UNLIKELY(t->chain != NULL))
    {
        LOGF("DomainResolver: prepare hook must be configured before chaining");
        abortProgramNow(1);
    }

    domainresolver_tstate_t *ts                = tunnelGetState(t);
    uint32_t                 aligned_user_size = 0;
    if (UNLIKELY(! tunnelTryAlignLineStateSize((size_t) user_lstate_size, &aligned_user_size)))
    {
        LOGF("DomainResolver: prepare hook line state is too large");
        abortProgramNow(1);
    }

    const uint32_t resolver_state_size = tunnelGetCorrectAlignedLineStateSize(sizeof(domainresolver_lstate_t));

    if (UNLIKELY(aligned_user_size > UINT32_MAX - resolver_state_size))
    {
        LOGF("DomainResolver: prepare hook line state is too large");
        abortProgramNow(1);
    }

    ts->prepare_owner       = owner;
    ts->prepare             = prepare;
    ts->user_lstate_destroy = destroy;
    ts->user_lstate_offset  = resolver_state_size;
    ts->user_lstate_size    = aligned_user_size;

    t->lstate_size = ts->user_lstate_offset + ts->user_lstate_size;
}

void *domainresolverTunnelGetUserLineState(tunnel_t *t, line_t *l)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);
    return domainresolverGetUserLineState(ts, lineGetState(l, t));
}

void domainresolverTunnelSetProvider(tunnel_t *helper, tunnel_t *provider)
{
    assert(helper != provider && helper->chain == NULL && provider != NULL);
    domainresolver_tstate_t *ts = tunnelGetState(helper);
    assert(ts->mode == kDomainResolverModeNative && ts->dns_workers == NULL);
    ts->provider = provider;
}

bool domainresolverTunnelResolutionEnabled(tunnel_t *resolver)
{
    return ((domainresolver_tstate_t *) tunnelGetState(resolver))->resolve;
}

enum domain_strategy domainresolverTunnelStrategy(tunnel_t *resolver)
{
    return ((domainresolver_tstate_t *) tunnelGetState(resolver))->strategy;
}

static tunnel_t *domainresolverEffectiveProvider(tunnel_t *provider)
{
    domainresolver_tstate_t *ts = tunnelGetState(provider);
    return ts->provider != NULL ? ts->provider : provider;
}

int domainresolverTunnelResolve(tunnel_t *provider, line_t *line, const char *domain, const char *service, int socktype,
                                LineDnsResolveFn cb, tunnel_t *callback_tunnel, void *userdata)
{
    assert(lineIsOnCurrentWorker(line));
    if (! domainresolverTunnelResolutionEnabled(provider))
        return ARES_EBADNAME;
    const domainresolver_tstate_t *consumer = tunnelGetState(provider);
    const int                      family   = dnsstrategyQueryFamily(
        consumer->use_line_strategy ? lineGetDestinationAddressContext(line)->domain_strategy : consumer->strategy);
    provider                    = domainresolverEffectiveProvider(provider);
    domainresolver_tstate_t *ts = tunnelGetState(provider);
    if (! ts->resolve)
        return ARES_EBADNAME;
    if (ts->mode == kDomainResolverModeNative && family == AF_UNSPEC)
        return lineResolveDomainServiceAsync(line, domain, service, socktype, cb, callback_tunnel, userdata);
    dns_resolver_t *resolver = NULL;
    if (ts->mode != kDomainResolverModeNative)
    {
        domainresolver_transport_t *transport = domainresolverGetTransportForLine(provider, line);
        if (transport == NULL)
            return ARES_ENOTINITIALIZED;
        resolver = domainresolverTransportResolver(transport);
    }
    return lineResolveDomainOnResolverFamilyAsync(
        line, resolver, domain, service, socktype, family, cb, callback_tunnel, userdata);
}

int domainresolverTunnelResolveRawWithStrategy(tunnel_t *provider, line_t *line, const char *domain,
                                               const char *service, int socktype, enum domain_strategy strategy,
                                               dns_resolve_cb cb, void *userdata)
{
    assert(lineIsOnCurrentWorker(line));
    if (! domainresolverTunnelResolutionEnabled(provider))
        return ARES_EBADNAME;
    provider                    = domainresolverEffectiveProvider(provider);
    domainresolver_tstate_t *ts = tunnelGetState(provider);
    if (! ts->resolve)
        return ARES_EBADNAME;
    const int family = dnsstrategyQueryFamily(strategy);
    if (ts->mode == kDomainResolverModeNative)
        return family == AF_UNSPEC
                   ? workerResolveDomainServiceAsync(lineGetWID(line), domain, service, socktype, cb, userdata)
                   : workerResolveDomainServiceFamilyAsync(
                         lineGetWID(line), domain, service, socktype, family, cb, userdata);
    domainresolver_transport_t *transport = domainresolverGetTransportForLine(provider, line);
    return transport == NULL
               ? ARES_ENOTINITIALIZED
               : asyncdnsResolveFamily(
                     domainresolverTransportResolver(transport), domain, service, socktype, family, cb, userdata);
}

int domainresolverTunnelResolveRaw(tunnel_t *provider, line_t *line, const char *domain, const char *service,
                                   int socktype, dns_resolve_cb cb, void *userdata)
{
    const domainresolver_tstate_t *ts = tunnelGetState(provider);
    enum domain_strategy           strategy =
        ts->use_line_strategy ? lineGetDestinationAddressContext(line)->domain_strategy : ts->strategy;
    return domainresolverTunnelResolveRawWithStrategy(
        provider, line, domain, service, socktype, strategy, cb, userdata);
}
