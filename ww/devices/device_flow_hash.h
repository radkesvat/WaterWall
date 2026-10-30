#pragma once

#include "wplatform.h"

#include <stdbool.h>
#include <stdint.h>

/*
 * Computes the full 64-bit flow hash of a parseable IP packet. Both directions
 * of one flow produce the same value, which is what makes it usable as a stable
 * per-flow identity and not only as a worker index. Returns false for malformed
 * or unsupported packets without touching *out_hash.
 *
 * "Malformed" is checked structurally, not merely against the buffer size: the
 * version nibble must be 4 or 6, an IPv4 header length must be 20..60 bytes and
 * fit, and the declared length (IPv4 total length, IPv6 payload length) must
 * describe a packet that both contains its own header and fits in the buffer.
 * Transport ports are read only when the declared length covers them, so
 * trailing bytes that follow a short packet in the same buffer never reach the
 * hash.
 *
 * Scope notes, unchanged from the worker selection this hash now backs:
 *
 *   - every IPv4 fragment of one datagram agrees (the IP identification stands
 *     in for the transport ports), but a fragmented datagram may hash
 *     differently from the unfragmented packets of the surrounding flow;
 *   - IPv6 extension headers are not walked, so ports are only read when the
 *     first next-header is already TCP or UDP;
 *   - an IPv6 payload length of zero is rejected. RFC 2675 makes it the marker
 *     for a jumbogram whose real size lives in a Hop-by-Hop Jumbo Payload
 *     option, and without walking extension headers a real jumbogram cannot be
 *     told from a malformed header.
 *
 * Protocols without ports (ICMP, ESP, anything else) are hashed on the address
 * pair and protocol number, so every packet between two hosts for one such
 * protocol shares a flow. The exception is a ported protocol, below.
 */
bool deviceFlowAffinityHash(const uint8_t *packet, uint32_t length, uint64_t *out_hash);

/*
 * Ported protocols. A transform such as IpManipulator's protocol swap replaces
 * the IP protocol number of a TCP/UDP packet but leaves its transport header at
 * the start of the IP payload. A device that is told such a protocol by the
 * chain it belongs to reads those two 16-bit values as ports: the hash below and
 * the Linux capture steering both use them. They may be obfuscated byte-wise
 * with a constant key because both hashes are symmetric, so the packets of one
 * inner flow keep one worker and one receive queue in either direction while
 * different flows spread. Every other protocol keeps hashing on the address pair
 * and protocol only.
 *
 * The set belongs to one device session, never to the process: a protocol number
 * names a header layout only inside the chain that declared it. TCP and UDP are
 * always ported and are not stored. A full set refuses further protocols.
 */
enum
{
    kDeviceFlowPortedProtocolMax = 2
};

typedef struct device_flow_ported_set_s
{
    uint8_t protocols[kDeviceFlowPortedProtocolMax]; /* ascending */
    uint8_t count;
} device_flow_ported_set_t;

/* Adds a protocol (a duplicate, TCP and UDP succeed without storing anything); false when the set is full. */
bool deviceFlowPortedSetAdd(device_flow_ported_set_t *set, uint8_t protocol);
/* TCP and UDP are always contained; a NULL set holds nothing else. */
bool deviceFlowPortedSetContains(const device_flow_ported_set_t *set, uint8_t protocol);

/* deviceFlowAffinityHash() that also reads the ports of the protocols in `ported` (NULL: native ports only). */
bool deviceFlowAffinityHashWithPorts(const uint8_t *packet, uint32_t length, const device_flow_ported_set_t *ported,
                                     uint64_t *out_hash);
