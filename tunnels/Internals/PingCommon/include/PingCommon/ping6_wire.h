#ifndef PING_COMMON_PING6_WIRE_H_
#define PING_COMMON_PING6_WIRE_H_

#include "PingCommon/ping_wire.h"

#include "lwip/prot/icmp6.h"

enum
{
    kPing6WireProtocol           = 58,
    kPing6WireIpv6InIpv4Protocol = 41,
    kPing6WireIpv6HeaderLength   = 40,
    kPing6WireEchoRequest        = ICMP6_TYPE_EREQ,
    kPing6WireEchoReply          = ICMP6_TYPE_EREP,
    kPing6WireIpv4HeaderLength   = kPingWireIpv4HeaderLength,
    kPing6WireIcmpHeaderLength   = sizeof(struct icmp6_echo_hdr),
    /* Direct-mode constants; use ping6wireOverhead() for an instance. */
    kPing6WireEncapsulationOverhead          = kPing6WireIcmpHeaderLength + 1,
    kPing6WireMaxInnerPacketLength           = kMaxAllowedPacketLength - kPing6WireEncapsulationOverhead,
    kPing6WireIpv6InIpv4Overhead             = kPing6WireIpv6HeaderLength + kPing6WireEncapsulationOverhead,
    kPing6WireIpv6InIpv4MaxInnerPacketLength = kMaxAllowedPacketLength - kPing6WireIpv6InIpv4Overhead,
};

_Static_assert(kPing6WireIcmpHeaderLength == 8, "Ping6 requires an 8-byte ICMPv6 Echo header");
_Static_assert(kPing6WireEncapsulationOverhead == 9, "Ping6 padding contract changed unexpectedly");
_Static_assert(kPing6WireMaxInnerPacketLength == 1491, "Ping6 maximum inner length changed unexpectedly");
_Static_assert(kPing6WireIpv6InIpv4Overhead == 49, "Ping6 IPv6-in-IPv4 padding contract changed unexpectedly");
_Static_assert(kPing6WireIpv6InIpv4MaxInnerPacketLength == 1451,
               "Ping6 IPv6-in-IPv4 maximum length changed unexpectedly");

typedef enum ping6_wire_mode_e
{
    kPing6WireDirect = 0,
    kPing6WireIpv6InIpv4,
} ping6_wire_mode_t;

typedef struct ping6_wire_config_s
{
    /* Actual inner endpoints in ipv6-in-ipv4; ignored in direct mode. */
    ip6_addr_t        local_ipv6;
    ip6_addr_t        peer_ipv6;
    uint16_t          identifier;
    ping6_wire_mode_t mode;
} ping6_wire_config_t;

/* The shared view carries actual IPv4 IHL and validated Echo offset separately. */
typedef ping_wire_envelope_t ping6_wire_envelope_t;

/* Parse exactly one bare address; lwIP's parsers alone accept trailing text and malformed fields. */
WW_EXPORT bool ping6wireParseIpv4Text(const char *text, uint32_t *ipv4_out);
WW_EXPORT bool ping6wireParseIpv6Text(const char *text, ip6_addr_t *address_out);
/* Configuration policy is separate from lexical IPv6 parsing. */
WW_EXPORT bool ping6wireEndpointIsAdmissible(const ip6_addr_t *address);

WW_EXPORT uint16_t    ping6wireOverhead(const ping6_wire_config_t *config);
WW_EXPORT uint8_t     ping6wireCarrierProtocol(const ping6_wire_config_t *config);
WW_EXPORT const char *ping6wireEchoRequestError(const sbuf_t *buf, const ping6_wire_config_t *config);
WW_EXPORT const char *ping6wirePrepareEchoRequest(sbuf_t *buf, const ping6_wire_config_t *config);

WW_EXPORT bool ping6wireEchoRequestPreflight(const sbuf_t *buf, const ping6_wire_config_t *config);
WW_EXPORT bool ping6wireBuildEchoRequest(sbuf_t *buf, const ping6_wire_config_t *config, uint16_t sequence);
WW_EXPORT ping_wire_inbound_kind_t ping6wireParseInbound(const uint8_t *packet, uint32_t length,
                                                         const ping6_wire_config_t *config,
                                                         ping6_wire_envelope_t     *envelope_out);
WW_EXPORT bool                     ping6wireBuildEchoReply(sbuf_t *buf, const ping6_wire_config_t *config,
                                                           const ping6_wire_envelope_t *request, uint16_t ipv4_identification);
WW_EXPORT bool                     ping6wireStripEchoRequest(sbuf_t *buf, const ping6_wire_envelope_t *request);
/* Admit the incoming envelope and endpoint pair before repairing visible checksums only. */
WW_EXPORT bool ping6wireRecalculateCarrierChecksums(sbuf_t *buf, const ping6_wire_config_t *config);

#endif /* PING_COMMON_PING6_WIRE_H_ */
