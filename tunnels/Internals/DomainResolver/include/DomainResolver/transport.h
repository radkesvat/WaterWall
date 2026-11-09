#pragma once

#include "wwapi.h"

typedef struct domainresolver_transport_s domainresolver_transport_t;

domainresolver_transport_t *domainresolverTransportCreate(tunnel_t *owner, tunnel_t *egress, wid_t wid,
                                                          const asyncdns_options_t *options);
dns_resolver_t             *domainresolverTransportResolver(domainresolver_transport_t *transport);
void                        domainresolverTransportQuiesce(domainresolver_transport_t *transport);
void                        domainresolverTransportDestroy(domainresolver_transport_t *transport);

void domainresolverTransportEst(tunnel_t *owner, line_t *line);
void domainresolverTransportFinish(tunnel_t *owner, line_t *line);
void domainresolverTransportPayload(tunnel_t *owner, line_t *line, sbuf_t *buf);
void domainresolverTransportPause(tunnel_t *owner, line_t *line);
void domainresolverTransportResume(tunnel_t *owner, line_t *line);
