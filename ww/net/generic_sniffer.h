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

    // Upper bound on a sniffed DNS query QDCOUNT. Stub resolvers send 1; mDNS may batch several questions.
    kGenericSnifferDnsMaxQuestions = 64,
};

generic_sniffer_result_t genericsnifferSniffHttp1Host(const uint8_t *payload, uint32_t payload_len, const uint8_t **host,
                                                      uint32_t *host_len);
void                     genericsnifferStripHostPortAndDot(const uint8_t **host, uint32_t *host_len);
generic_sniffer_result_t genericsnifferSniffHttp1Request(const uint8_t *payload, uint32_t payload_len);
generic_sniffer_result_t genericsnifferSniffHttp1UpgradeHeader(const uint8_t *payload, uint32_t payload_len);
generic_sniffer_result_t genericsnifferSniffTlsClientHello(const uint8_t *payload, uint32_t payload_len);
/** The returned SNI borrows payload for one-record input or scratch for fragmented
 * input. Keep both alive until the caller has consumed the returned view. */
generic_sniffer_result_t genericsnifferSniffTlsClientHelloSni(const uint8_t *payload, uint32_t payload_len,
                                                              uint8_t         scratch[kGenericSnifferMaxWindowBytes],
                                                              const uint8_t **host, uint32_t *host_len);
generic_sniffer_result_t genericsnifferSniffBittorrentHandshake(const uint8_t *payload, uint32_t payload_len);
/** Strict prefix validator for a DNS query message as carried in one UDP datagram
 * (no TCP length prefix). It checks the 12-byte header (QR=0, OPCODE=0 standard
 * query, 1 <= QDCOUNT <= kGenericSnifferDnsMaxQuestions) and the first question
 * (uncompressed QNAME of 1..63-byte labels, encoded length <= 255, followed by
 * QTYPE and a known QCLASS: IN, CH, HS, NONE or ANY, with or without the mDNS
 * unicast-response bit). Later sections are not inspected. Empty input returns
 * NeedMore; any other input is decided immediately (see the definition). */
generic_sniffer_result_t genericsnifferSniffDnsQuery(const uint8_t *payload, uint32_t payload_len);
