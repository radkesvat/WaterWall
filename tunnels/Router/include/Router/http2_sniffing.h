#pragma once

#include "wlibc.h"

typedef enum router_http2_domain_result_e
{
    kRouterHttp2DomainFound    = 0,
    kRouterHttp2DomainNeedMore = 1,
    kRouterHttp2DomainMissing  = 2
} router_http2_domain_result_t;

router_http2_domain_result_t routerHttp2SniffDomain(const uint8_t *payload, uint32_t payload_len, uint8_t *host,
                                                    uint32_t host_cap, uint32_t *host_len);
