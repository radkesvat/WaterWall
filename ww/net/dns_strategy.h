#pragma once

#include "address_context.h"
#include "async_dns.h"

bool dnsstrategyFamilyAllowedByStrategy(int family, enum domain_strategy strategy);
bool dnsstrategyFamilyPreferredByStrategy(int family, enum domain_strategy strategy);
const dns_resolved_addr_t *dnsstrategySelectResolvedAddress(const dns_resolved_addr_t *addrs, size_t naddrs,
                                                            enum domain_strategy strategy);
bool dnsstrategyApplyResolvedAddress(address_context_t *ctx, const dns_resolved_addr_t *resolved);
