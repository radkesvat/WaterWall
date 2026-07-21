#pragma once

#include "wwapi.h"

typedef enum domainresolver_direction_e
{
    kDomainResolverDirectionNone = 0,
    kDomainResolverDirectionUpstream,
    kDomainResolverDirectionDownstream
} domainresolver_direction_t;

typedef bool (*domainresolver_prepare_fn)(tunnel_t *resolver, tunnel_t *owner, line_t *line,
                                          domainresolver_direction_t direction, void *user_lstate);
typedef void (*domainresolver_user_lstate_destroy_fn)(tunnel_t *resolver, tunnel_t *owner, line_t *line,
                                                      void *user_lstate);

WW_EXPORT node_t nodeDomainResolverGet(void);
WW_EXPORT void   domainresolverTunnelUseLineStrategy(tunnel_t *t, bool enabled);
WW_EXPORT void   domainresolverTunnelAllowMissingDestination(tunnel_t *t, bool enabled);
WW_EXPORT void   domainresolverTunnelSetPrepareHook(tunnel_t *t, tunnel_t *owner, uint32_t user_lstate_size,
                                                    domainresolver_prepare_fn             prepare,
                                                    domainresolver_user_lstate_destroy_fn destroy);
WW_EXPORT void  *domainresolverTunnelGetUserLineState(tunnel_t *t, line_t *l);
