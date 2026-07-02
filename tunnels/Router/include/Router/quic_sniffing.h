#pragma once

#include "generic_sniffer.h"

generic_sniffer_result_t routerQuicSniffClientHelloSni(const uint8_t *payload, uint32_t payload_len, uint8_t *host,
                                                       uint32_t host_cap, uint32_t *host_len);
