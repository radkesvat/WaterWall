#pragma once

#include "wwapi.h"

/* Runs during upstream Init, before resolving the line's destination. Embedded
 * preparation state remains valid through next Init. Consumers must copy any
 * data they need afterward: settled normal lines destroy it before bypass. */
typedef bool (*domainresolver_prepare_fn)(tunnel_t *resolver, tunnel_t *owner, line_t *line, void *user_lstate);
typedef void (*domainresolver_user_lstate_destroy_fn)(tunnel_t *resolver, tunnel_t *owner, line_t *line,
                                                      void *user_lstate);

WW_EXPORT node_t nodeDomainResolverGet(void);
WW_EXPORT void   domainresolverTunnelUseLineStrategy(tunnel_t *t, bool enabled);
WW_EXPORT void   domainresolverTunnelAllowMissingDestination(tunnel_t *t, bool enabled);
WW_EXPORT void   domainresolverTunnelSetPrepareHook(tunnel_t *t, tunnel_t *owner, uint32_t user_lstate_size,
                                                    domainresolver_prepare_fn             prepare,
                                                    domainresolver_user_lstate_destroy_fn destroy);
WW_EXPORT void  *domainresolverTunnelGetUserLineState(tunnel_t *t, line_t *l);

/* Call after the embedding owner's topology is assembled, before indexing.
 * A NULL shared entry requires a separately bound dns-next for chain mode. */
WW_EXPORT bool domainresolverTunnelAttachEmbedded(tunnel_t *resolver, tunnel_t *owner, tunnel_t *shared_entry);
/* A private helper keeps destination preparation but borrows this provider.
 * Configure before chaining; only the provider owns channels and DNS branches. */
WW_EXPORT void                 domainresolverTunnelSetProvider(tunnel_t *helper, tunnel_t *provider);
WW_EXPORT bool                 domainresolverTunnelResolutionEnabled(tunnel_t *resolver);
WW_EXPORT enum domain_strategy domainresolverTunnelStrategy(tunnel_t *resolver);
WW_EXPORT int domainresolverTunnelResolve(tunnel_t *provider, line_t *line, const char *domain, const char *service,
                                          int socktype, LineDnsResolveFn cb, tunnel_t *callback_tunnel, void *userdata);
/* Raw completion is never suppressed for a dead line or resolver cleanup.
 * The caller retains its existing request/line reference and settlement rules. */
WW_EXPORT int domainresolverTunnelResolveRaw(tunnel_t *provider, line_t *line, const char *domain, const char *service,
                                             int socktype, dns_resolve_cb cb, void *userdata);
/* Use the request's snapshotted strategy when its destination is independent
 * of the line's mutable destination context. Completion has the raw contract. */
WW_EXPORT int domainresolverTunnelResolveRawWithStrategy(tunnel_t *provider, line_t *line, const char *domain,
                                                         const char *service, int socktype,
                                                         enum domain_strategy strategy, dns_resolve_cb cb,
                                                         void *userdata);
