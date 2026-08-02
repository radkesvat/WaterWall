#pragma once

/*
 * Strict, pointer-free views over complete IPv4 packets and their TCP/UDP
 * transport headers. Offsets remain valid when the owning buffer relocates.
 */

#include "wlibc.h"

typedef struct ipv4_packet_view_s
{
    uint32_t source_address;
    uint32_t destination_address;
    uint32_t tcp_sequence;
    uint32_t tcp_acknowledgment;
    uint32_t tcp_sequence_span;

    uint16_t ip_total_length;
    uint16_t ip_header_length;
    uint16_t transport_offset;
    uint16_t transport_length;
    uint16_t transport_header_length;
    uint16_t payload_offset;
    uint16_t payload_length;
    uint16_t fragment_state;
    uint16_t fragment_offset;
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t ip_identification;
    uint16_t udp_datagram_length;

    uint8_t protocol;
    uint8_t ttl;
    uint8_t tcp_flags;
    bool    more_fragments;
    bool    fragmented;
} ipv4_packet_view_t;

/** Parse and validate a complete IPv4 packet. Transport fields remain zero. */
bool ipv4packetviewParse(const uint8_t *packet, size_t available_length, ipv4_packet_view_t *view);

/**
 * Parse an IPv4 TCP packet whose transport header is present. A first fragment
 * may be inspected and is identified through @c fragmented; non-first
 * fragments are rejected because they do not carry the TCP header.
 */
bool ipv4packetviewParseTcp(const uint8_t *packet, size_t available_length, ipv4_packet_view_t *view);

/**
 * Parse an IPv4 UDP packet whose transport header is present. For a first
 * fragment, payload_length is the number of UDP payload bytes present in this
 * fragment while udp_datagram_length retains the declared UDP length.
 */
bool ipv4packetviewParseUdp(const uint8_t *packet, size_t available_length, ipv4_packet_view_t *view);

/** ECN-aware predicate for a payload-free flow-opening SYN. */
bool ipv4packetviewTcpFlagsAreOpeningSyn(uint8_t tcp_flags, uint32_t tcp_payload_length);

/** Apply the ECN-aware opening-SYN predicate to a parsed TCP view. */
bool ipv4packetviewIsOpeningTcpSyn(const ipv4_packet_view_t *view);

static inline bool ipv4packetviewTcpHasAnyFlags(const ipv4_packet_view_t *view, uint8_t flags)
{
    return view != NULL && (view->tcp_flags & flags) != 0;
}

static inline bool ipv4packetviewTcpHasAllFlags(const ipv4_packet_view_t *view, uint8_t flags)
{
    return view != NULL && (view->tcp_flags & flags) == flags;
}
