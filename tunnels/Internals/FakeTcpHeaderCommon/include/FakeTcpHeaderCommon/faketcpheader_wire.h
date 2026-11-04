#ifndef FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_
#define FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_

/*
 * Shared fake-TCP codec for FakeTcpHeaderClient and FakeTcpHeaderServer:
 *
 *   existing IPv4 (actual IHL) | fake TCP (20 B + options) | protocol byte | native body
 *
 * The IPv4 header is reused, including its addresses and options. The native
 * TCP/UDP checksum carries zero address contributions while encoded. Nodes
 * retain callback direction, buffer ownership and diagnostics; helpers use no line.
 */

#include "wwapi.h"

enum
{
    kFakeTcpHeaderWireTcpHeaderLength  = TCP_HLEN,
    kFakeTcpHeaderWireMaxOptionsLength = 40,
    kFakeTcpHeaderWireProtocolLength   = 1,
    kFakeTcpHeaderWireRequiredPaddingLeft =
        TCP_HLEN + kFakeTcpHeaderWireMaxOptionsLength + kFakeTcpHeaderWireProtocolLength,
    kFakeTcpHeaderWireMaxCarrierLength   = kMaxAllowedPacketLength,
    kFakeTcpHeaderWireTcpFlags           = TCP_ACK | TCP_PSH,
    kFakeTcpHeaderWireMaxClientPortCount = 1024,
};

_Static_assert(kFakeTcpHeaderWireRequiredPaddingLeft == 61, "FakeTcpHeader padding contract changed unexpectedly");
_Static_assert(kFakeTcpHeaderWireTcpFlags == 0x18, "FakeTcpHeader carriers use ACK|PSH");

/* Which endpoint of the carrier pair is encoding or decoding. */
typedef enum faketcpheader_wire_side_e
{
    kFakeTcpHeaderWireClient = 0,
    kFakeTcpHeaderWireServer,
} faketcpheader_wire_side_t;

typedef enum faketcpheader_field_mode_e
{
    kFakeTcpHeaderFieldNumeric = 0,
    kFakeTcpHeaderFieldRandomNode,
    kFakeTcpHeaderFieldRandomPort,
    kFakeTcpHeaderFieldRandomPacket,
} faketcpheader_field_mode_t;

/* Host-order outgoing TCP template. Peers must agree on ports; their outgoing
 * TCP templates and options lengths can differ. Each packet carries its protocol. */
typedef struct faketcpheader_wire_config_s
{
    faketcpheader_field_mode_t sequence_mode;
    faketcpheader_field_mode_t acknowledgment_mode;
    uint32_t                   sequence;
    uint32_t                   acknowledgment;
    uint16_t                   window;
    uint16_t                   urgent_pointer;
    uint16_t                   server_port;
    uint16_t                   client_port;
    uint16_t                   client_port_count;
    bool                       increment_sequence;
    bool                       increment_acknowledgment;
    uint8_t                    options_length;
    uint8_t                    options[kFakeTcpHeaderWireMaxOptionsLength];
} faketcpheader_wire_config_t;

/* Per-port random seeds remain stored even when increments are disabled. */
static inline bool faketcpheaderWireNeedsSequences(const faketcpheader_wire_config_t *config)
{
    return config->increment_sequence || config->sequence_mode == kFakeTcpHeaderFieldRandomPort;
}

static inline bool faketcpheaderWireNeedsAcknowledgments(const faketcpheader_wire_config_t *config)
{
    return config->increment_acknowledgment || config->acknowledgment_mode == kFakeTcpHeaderFieldRandomPort;
}

/* Optional sequence slots precede optional per-port ACK slots. Both arrays
 * share the node allocation; at most two 32-bit values per selected port. */
static inline size_t faketcpheaderWireStateCount(const faketcpheader_wire_config_t *config)
{
    return (size_t) config->client_port_count *
           ((size_t) faketcpheaderWireNeedsSequences(config) + (size_t) faketcpheaderWireNeedsAcknowledgments(config));
}

/* Every non-Ok value leaves all bytes (including headroom), cursor, length and
 * checksum-repair intent unchanged. The caller retains buffer ownership. */
typedef enum faketcpheader_wire_result_e
{
    kFakeTcpHeaderWireOk = 0,
    kFakeTcpHeaderWireMalformedNative,
    kFakeTcpHeaderWireFragmented,
    kFakeTcpHeaderWireOversizedNative,
    kFakeTcpHeaderWireMissingHeadroom,
    kFakeTcpHeaderWireNativeRepairFailed,
    kFakeTcpHeaderWireMalformedCarrier,
    kFakeTcpHeaderWireCarrierPorts,
    kFakeTcpHeaderWireCarrierChecksum,
    kFakeTcpHeaderWireNativeFraming,
} faketcpheader_wire_result_t;

static inline uint16_t faketcpheaderWireTcpHeaderLength(const faketcpheader_wire_config_t *config)
{
    assert(config->options_length <= kFakeTcpHeaderWireMaxOptionsLength && config->options_length % 4U == 0);
    return (uint16_t) (kFakeTcpHeaderWireTcpHeaderLength + config->options_length);
}

static inline uint16_t faketcpheaderWireOverhead(const faketcpheader_wire_config_t *config)
{
    return (uint16_t) (faketcpheaderWireTcpHeaderLength(config) + kFakeTcpHeaderWireProtocolLength);
}

static inline uint16_t faketcpheaderWireMaxNativeLength(const faketcpheader_wire_config_t *config)
{
    return (uint16_t) (kFakeTcpHeaderWireMaxCarrierLength - faketcpheaderWireOverhead(config));
}

/* Short static description of a result, for drop diagnostics. */
WW_EXPORT const char *faketcpheaderWireResultName(faketcpheader_wire_result_t result);

/* deviceFlowWorkerHash() of the native packet modulo the selected client port count, or 0
 * when unhashable. Reversed native tuples select the same client port; address
 * rewrites can change that tuple and each encoder must see a stable flow. */
WW_EXPORT uint16_t faketcpheaderWirePortIndex(const faketcpheader_wire_config_t *config, const uint8_t *native,
                                              uint32_t native_length);

/* Initialize once before publishing the node, after runtime RNG initialization.
 * Resolve random_node fields and independently seed random_port fields. values
 * has StateCount atomic entries, or may be NULL when that count is zero.
 * Config is immutable after initialization; do not copy live counters. */
WW_EXPORT void faketcpheaderWireInitState(faketcpheader_wire_config_t *config, atomic_u32_t *values);

/* Insert fake TCP and a protocol byte into one complete unfragmented IPv4 packet.
 * Honor native repair intent before normalizing TCP/UDP checksum addresses to zero.
 * Otherwise retain native checksum residuals. Sequence incrementing reserves the
 * selected port's fake TCP payload bytes from values; ACK incrementing uses its
 * current value then adds one per accepted encoding. Refusals advance neither.
 * Fixed random_port fields read their stored values without advancing. ACK
 * random_packet draws only after every expected refusal, before checksumming.
 * Requires initialized field state and an ordinary buffer. */
WW_EXPORT faketcpheader_wire_result_t faketcpheaderWireEncode(const faketcpheader_wire_config_t *config,
                                                              atomic_u32_t *values, faketcpheader_wire_side_t side,
                                                              sbuf_t *buf);

/* Verify and remove fake TCP and the tag, restore its protocol and TCP/UDP checksum
 * current address contributions. A pending request waives visible checksums only
 * and is consumed on success; it never repairs hidden native corruption.
 * Requires an ordinary buffer. */
WW_EXPORT faketcpheader_wire_result_t faketcpheaderWireDecode(const faketcpheader_wire_config_t *config,
                                                              faketcpheader_wire_side_t side, sbuf_t *buf);

/* Strict settings loader: client-port selects one port; client-port-range selects
 * inclusive endpoints. These settings are mutually exclusive. Omitting both
 * selects 40001..40016; omitted settings and {} select ordinary defaults.
 * Unknown settings are refused. Failures name the node/settings key and leave
 * *out unchanged. */
WW_EXPORT bool faketcpheaderWireLoadSettings(const cJSON *settings, const char *node_name,
                                             faketcpheader_wire_config_t *out);

#endif /* FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_ */
