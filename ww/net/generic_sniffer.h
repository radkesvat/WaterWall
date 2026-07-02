#pragma once

#include "wlibc.h"

typedef enum generic_sniffer_result_e
{
    kGenericSnifferNeedMore = 0,
    kGenericSnifferMissing  = 1,
    kGenericSnifferFound    = 2
} generic_sniffer_result_t;

enum
{
    // Longest HTTP method token currently tested ("CONNECT "/"OPTIONS ") is 8 bytes.
    kGenericSnifferMethodDecideBytes = 8,

    // Keep first-payload protocol sniffing bounded.
    kGenericSnifferMaxWindowBytes = 8192,
};

generic_sniffer_result_t genericsnifferSniffHttp1Host(const uint8_t *payload, uint32_t payload_len, const uint8_t **host,
                                                      uint32_t *host_len);
void                     genericsnifferStripHostPortAndDot(const uint8_t **host, uint32_t *host_len);
generic_sniffer_result_t genericsnifferSniffHttp1Request(const uint8_t *payload, uint32_t payload_len);
generic_sniffer_result_t genericsnifferSniffHttp1UpgradeHeader(const uint8_t *payload, uint32_t payload_len);
generic_sniffer_result_t genericsnifferSniffTlsClientHello(const uint8_t *payload, uint32_t payload_len);
generic_sniffer_result_t genericsnifferSniffTlsClientHelloSni(const uint8_t *payload, uint32_t payload_len,
                                                              const uint8_t **host, uint32_t *host_len);
generic_sniffer_result_t genericsnifferSniffBittorrentHandshake(const uint8_t *payload, uint32_t payload_len);
