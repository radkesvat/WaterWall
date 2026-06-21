#pragma once

#include "wlibc.h"

typedef enum protocol_sniff_result_e
{
    kProtocolSniffNeedMore = 0,
    kProtocolSniffMissing  = 1,
    kProtocolSniffFound    = 2
} protocol_sniff_result_t;

enum
{
    // Longest HTTP method token currently tested ("CONNECT "/"OPTIONS ") is 8 bytes.
    kProtocolSniffMethodDecideBytes = 8,

    // Keep first-payload protocol sniffing bounded.
    kProtocolSniffMaxWindowBytes = 8192,
};

protocol_sniff_result_t protocolsniffHttpHost(const uint8_t *payload, uint32_t payload_len,
                                              const uint8_t **host, uint32_t *host_len);
protocol_sniff_result_t protocolsniffHttpUpgradeHeader(const uint8_t *payload, uint32_t payload_len);
protocol_sniff_result_t protocolsniffTlsClientHelloSni(const uint8_t *payload, uint32_t payload_len,
                                                       const uint8_t **host, uint32_t *host_len);
