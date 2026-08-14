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
    if (UNLIKELY(! tunnelTryAlignStateSize((size_t) user_lstate_size, &aligned_user_size)))
    {
        LOGF("DomainResolver: prepare hook line state is too large");
        abortProgramNow(1);
    }

    uint32_t resolver_state_size = 0;
    if (UNLIKELY(! tunnelTryAlignStateSize(sizeof(domainresolver_lstate_t), &resolver_state_size)))
    {
        LOGF("DomainResolver: internal line state is too large");
        abortProgramNow(1);
    }

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
    if (ts->user_lstate_size == 0)
    {
        return NULL;
    }

    return domainresolverGetUserLineState(ts, lineGetState(l, t));
}
