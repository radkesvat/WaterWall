#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeDomainResolverGet(void);
WW_EXPORT void   domainresolverTunnelUseLineStrategy(tunnel_t *t, bool enabled);
WW_EXPORT void   domainresolverTunnelAllowMissingDestination(tunnel_t *t, bool enabled);
