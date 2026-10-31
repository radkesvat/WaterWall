#ifndef FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_
#define FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_

/*
 * Shared fake-TCP carrier codec for FakeTcpHeaderClient and FakeTcpHeaderServer.
 *
 *   outer IPv4 (20 B) | TCP header (20 B + options) | complete inner IPv4 packet
 *
 * The codec owns the deterministic packet mechanics, the per-flow carrier port
 * mapping and the strict settings parser. The nodes retain callback direction,
 * buffer ownership and drop diagnostics. These helpers never access a line.
 */

#include "wwapi.h"

enum
{
    kFakeTcpHeaderWireIpv4HeaderLength    = IP_HLEN,
    kFakeTcpHeaderWireTcpHeaderLength     = TCP_HLEN,
    kFakeTcpHeaderWireMaxOptionsLength    = 40,
    kFakeTcpHeaderWireRequiredPaddingLeft = IP_HLEN + TCP_HLEN + kFakeTcpHeaderWireMaxOptionsLength,
    kFakeTcpHeaderWireMaxCarrierLength    = kMaxAllowedPacketLength,
    kFakeTcpHeaderWireTtl                 = 64,
    kFakeTcpHeaderWireTcpFlags            = TCP_ACK | TCP_PSH,
    kFakeTcpHeaderWireMaxClientPortCount  = 1024,
};

_Static_assert(kFakeTcpHeaderWireRequiredPaddingLeft == 80, "FakeTcpHeader padding contract changed unexpectedly");
_Static_assert(kFakeTcpHeaderWireTcpFlags == 0x18, "FakeTcpHeader carriers use ACK|PSH");

/* Which endpoint of the carrier pair is encoding or decoding. */
typedef enum faketcpheader_wire_side_e
{
    kFakeTcpHeaderWireClient = 0,
    kFakeTcpHeaderWireServer,
} faketcpheader_wire_side_t;

/* Host-order TCP header template; identical on both nodes of a pair. */
typedef struct faketcpheader_wire_config_s
{
    uint32_t sequence;
    uint32_t acknowledgment;
    uint16_t window;
    uint16_t urgent_pointer;
    uint16_t server_port;
    uint16_t client_port;
    uint16_t client_port_count;
    uint8_t  options_length;
    uint8_t  options[kFakeTcpHeaderWireMaxOptionsLength];
} faketcpheader_wire_config_t;

/* Every non-Ok value is a refusal that left bytes, cursor, length and the
 * checksum-repair request unchanged; the caller keeps buffer ownership. */
typedef enum faketcpheader_wire_result_e
{
    kFakeTcpHeaderWireOk = 0,
    /* Encode: the input is not exactly one complete IPv4 packet. */
    kFakeTcpHeaderWireMalformedInner,
    /* Encode: the inner packet exceeds 1500 bytes minus the carrier overhead. */
    kFakeTcpHeaderWireOversizedInner,
    /* Encode: the buffer cannot prepend the carrier overhead. */
    kFakeTcpHeaderWireMissingHeadroom,
    /* Encode: a requested inner checksum repair was refused by the checksum API. */
    kFakeTcpHeaderWireInnerRepairFailed,
    /* Decode: not one complete unfragmented IPv4/TCP packet of at most 1500 bytes. */
    kFakeTcpHeaderWireMalformedCarrier,
    /* Decode: the carrier ports do not match this side's mapping. */
    kFakeTcpHeaderWireCarrierPorts,
    /* Decode: the outer IPv4 header or TCP checksum does not verify. */
    kFakeTcpHeaderWireOuterChecksum,
    /* Decode: the carrier payload is not exactly one complete IPv4 packet. */
    kFakeTcpHeaderWireInnerFraming,
} faketcpheader_wire_result_t;

static inline uint16_t faketcpheaderWireOverhead(const faketcpheader_wire_config_t *config)
{
    assert(config->options_length <= kFakeTcpHeaderWireMaxOptionsLength && config->options_length % 4U == 0);
    return (uint16_t) (kFakeTcpHeaderWireIpv4HeaderLength + kFakeTcpHeaderWireTcpHeaderLength + config->options_length);
}

static inline uint16_t faketcpheaderWireMaxInnerLength(const faketcpheader_wire_config_t *config)
{
    return (uint16_t) (kFakeTcpHeaderWireMaxCarrierLength - faketcpheaderWireOverhead(config));
}

/* Short static description of a result, for drop diagnostics. */
WW_EXPORT const char *faketcpheaderWireResultName(faketcpheader_wire_result_t result);

/* Carrier port offset of one inner packet: deviceFlowWorkerHash() modulo
 * client-port-count, or 0 when the packet cannot be hashed. Endpoint-symmetric,
 * so a request and its reply select the same client port. */
WW_EXPORT uint16_t faketcpheaderWirePortIndex(const faketcpheader_wire_config_t *config, const uint8_t *inner,
                                              uint32_t inner_length);

/* Prepend the carrier to one complete inner IPv4 packet in place. Inner
 * checksums are not inspected; a pending repair request is honored and then
 * cleared. Requires an ordinary (non-splice) buffer. */
WW_EXPORT faketcpheader_wire_result_t faketcpheaderWireEncode(const faketcpheader_wire_config_t *config,
                                                              faketcpheader_wire_side_t side, sbuf_t *buf);

/* Verify and strip one carrier in place, leaving the inner IPv4 packet. Outer
 * addresses are not checked; a pending repair request skips outer checksum
 * verification and is cleared. Requires an ordinary (non-splice) buffer. */
WW_EXPORT faketcpheader_wire_result_t faketcpheaderWireDecode(const faketcpheader_wire_config_t *config,
                                                              faketcpheader_wire_side_t side, sbuf_t *buf);

/* Strict settings loader shared by both nodes. NULL settings select every
 * default. Each failure logs "JSON Error: <node_name>->settings-><key> : ..."
 * and leaves *out unchanged. */
WW_EXPORT bool faketcpheaderWireLoadSettings(const cJSON *settings, const char *node_name,
                                             faketcpheader_wire_config_t *out);

#endif /* FAKE_TCP_HEADER_COMMON_FAKETCPHEADER_WIRE_H_ */
