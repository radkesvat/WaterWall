#ifndef FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_
#define FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_

/*
 * Shared fake-TCP codec for FakeTcpHeaderClient and FakeTcpHeaderServer:
 *
 *   existing IPv4 (actual IHL) | fake TCP (20 B + options) | native TCP/UDP
 *
 * The IPv4 header is reused, including its addresses and options. The native
 * transport checksum carries zero address contributions while encoded. Nodes
 * retain callback direction, buffer ownership and diagnostics; helpers use no line.
 */

#include "wwapi.h"

enum
{
    kFakeTcpHeaderWireTcpHeaderLength     = TCP_HLEN,
    kFakeTcpHeaderWireMaxOptionsLength    = 40,
    kFakeTcpHeaderWireRequiredPaddingLeft = TCP_HLEN + kFakeTcpHeaderWireMaxOptionsLength,
    kFakeTcpHeaderWireMaxCarrierLength    = kMaxAllowedPacketLength,
    kFakeTcpHeaderWireTcpFlags            = TCP_ACK | TCP_PSH,
    kFakeTcpHeaderWireMaxClientPortCount  = 1024,
};

_Static_assert(kFakeTcpHeaderWireRequiredPaddingLeft == 60, "FakeTcpHeader padding contract changed unexpectedly");
_Static_assert(kFakeTcpHeaderWireTcpFlags == 0x18, "FakeTcpHeader carriers use ACK|PSH");

/* Which endpoint of the carrier pair is encoding or decoding. */
typedef enum faketcpheader_wire_side_e
{
    kFakeTcpHeaderWireClient = 0,
    kFakeTcpHeaderWireServer,
} faketcpheader_wire_side_t;

/* Host-order outgoing TCP template. Peers must agree on payload_protocol and
 * ports; their outgoing TCP templates and options lengths can differ. */
typedef struct faketcpheader_wire_config_s
{
    uint32_t sequence;
    uint32_t acknowledgment;
    uint16_t window;
    uint16_t urgent_pointer;
    uint16_t server_port;
    uint16_t client_port;
    uint16_t client_port_count;
    uint8_t  payload_protocol;
    uint8_t  options_length;
    uint8_t  options[kFakeTcpHeaderWireMaxOptionsLength];
} faketcpheader_wire_config_t;

/* Every non-Ok value leaves all bytes (including headroom), cursor, length and
 * checksum-repair intent unchanged. The caller retains buffer ownership. */
typedef enum faketcpheader_wire_result_e
{
    kFakeTcpHeaderWireOk = 0,
    kFakeTcpHeaderWireMalformedNative,
    kFakeTcpHeaderWireNativeProtocol,
    kFakeTcpHeaderWireFragmented,
    kFakeTcpHeaderWireOversizedNative,
    kFakeTcpHeaderWireMissingHeadroom,
    kFakeTcpHeaderWireNativeRepairFailed,
    kFakeTcpHeaderWireMalformedCarrier,
    kFakeTcpHeaderWireCarrierPorts,
    kFakeTcpHeaderWireCarrierChecksum,
    kFakeTcpHeaderWireNativeFraming,
} faketcpheader_wire_result_t;

static inline uint16_t faketcpheaderWireOverhead(const faketcpheader_wire_config_t *config)
{
    assert(config->options_length <= kFakeTcpHeaderWireMaxOptionsLength && config->options_length % 4U == 0);
    return (uint16_t) (kFakeTcpHeaderWireTcpHeaderLength + config->options_length);
}

static inline uint16_t faketcpheaderWireMaxNativeLength(const faketcpheader_wire_config_t *config)
{
    return (uint16_t) (kFakeTcpHeaderWireMaxCarrierLength - faketcpheaderWireOverhead(config));
}

/* Short static description of a result, for drop diagnostics. */
WW_EXPORT const char *faketcpheaderWireResultName(faketcpheader_wire_result_t result);

/* deviceFlowWorkerHash() of the native packet modulo client-port-count, or 0
 * when unhashable. Reversed native tuples select the same client port; address
 * rewrites can change that tuple and each encoder must see a stable flow. */
WW_EXPORT uint16_t faketcpheaderWirePortIndex(const faketcpheader_wire_config_t *config, const uint8_t *native,
                                              uint32_t native_length);

/* Insert fake TCP into one complete unfragmented native IPv4 TCP/UDP packet.
 * Honor native repair intent before normalizing its checksum addresses to zero.
 * Otherwise retain native checksum residuals. Requires an ordinary buffer. */
WW_EXPORT faketcpheader_wire_result_t faketcpheaderWireEncode(const faketcpheader_wire_config_t *config,
                                                              faketcpheader_wire_side_t side, sbuf_t *buf);

/* Verify and remove fake TCP, restore payload_protocol and the native checksum's
 * current address contributions. A pending request waives visible checksums only
 * and is consumed on success; it never repairs hidden native corruption.
 * Requires an ordinary buffer. */
WW_EXPORT faketcpheader_wire_result_t faketcpheaderWireDecode(const faketcpheader_wire_config_t *config,
                                                              faketcpheader_wire_side_t side, sbuf_t *buf);

/* Strict settings loader: payload-protocol is a required integer, 6 or 17.
 * Other settings retain defaults. Failures name the node/settings key and leave
 * *out unchanged. */
WW_EXPORT bool faketcpheaderWireLoadSettings(const cJSON *settings, const char *node_name,
                                             faketcpheader_wire_config_t *out);

#endif /* FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_ */
