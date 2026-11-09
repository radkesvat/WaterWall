#pragma once

#include "wwapi.h"

#include "DnsLineClient/dns_line_client.h"

/* Runs during upstream Init, before resolving the line's destination. Embedded
 * preparation state remains valid through next Init. Consumers must copy any
 * data they need afterward: settled normal lines destroy it before bypass. */
typedef bool (*domainresolver_prepare_fn)(tunnel_t *resolver, tunnel_t *owner, line_t *line, void *user_lstate);
typedef void (*domainresolver_user_lstate_destroy_fn)(tunnel_t *resolver, tunnel_t *owner, line_t *line,
                                                      void *user_lstate);
/* Chain mode: sends upstream Init of an internally created DNS query line toward
 * the route that should carry it. Downstream callbacks of that line must arrive
 * back at the resolver (its next side). May destroy the line before returning. */
typedef void (*domainresolver_inject_fn)(tunnel_t *owner, line_t *l);

WW_EXPORT node_t nodeDomainResolverGet(void);
WW_EXPORT void   domainresolverTunnelUseLineStrategy(tunnel_t *t, bool enabled);
WW_EXPORT void   domainresolverTunnelAllowMissingDestination(tunnel_t *t, bool enabled);
WW_EXPORT void   domainresolverTunnelSetPrepareHook(tunnel_t *t, tunnel_t *owner, uint32_t user_lstate_size,
                                                    domainresolver_prepare_fn             prepare,
                                                    domainresolver_user_lstate_destroy_fn destroy);
WW_EXPORT void  *domainresolverTunnelGetUserLineState(tunnel_t *t, line_t *l);
/* Switch the resolver to "chain" mode before chaining: domains are resolved by
 * DNS queries sent over injected UDP lines through `inject(inject_owner, l)`. */
WW_EXPORT void domainresolverTunnelSetChainResolver(tunnel_t *t, const dnslineclient_config_t *cfg,
                                                    tunnel_t *inject_owner, domainresolver_inject_fn inject);
