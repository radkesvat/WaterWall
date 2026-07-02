#pragma once

#include "wlibc.h"

typedef enum router_quic_sni_result_e
{
    kRouterQuicSniFound    = 0,
    kRouterQuicSniNeedMore = 1,
    kRouterQuicSniMissing  = 2
} router_quic_sni_result_t;

router_quic_sni_result_t routerQuicSniffClientHelloSni(const uint8_t *payload, uint32_t payload_len, uint8_t *host,
                                                       uint32_t host_cap, uint32_t *host_len);
