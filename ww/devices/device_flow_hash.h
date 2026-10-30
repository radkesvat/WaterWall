#pragma once

#include "devices/device_opaque_flow_mode.h"
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
 * Full64 identity parser scope:
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
 * protocol shares a flow.
 */
bool deviceFlowAffinityHash(const uint8_t *packet, uint32_t length, uint64_t *out_hash);

/* Pure worker-selection hash. Network fields use explicit big-endian decoding,
 * including unaligned bytes. Encode E(address, word) = address XOR
 * (word * 0x9E3779B1), then independently mix each E with E ^= E >> 16;
 * E *= 0x85EBCA6B; E ^= E >> 13.
 * H = (mixed_src + mixed_dst) XOR protocol XOR fragment_key; H *= 0x9E3779B1;
 * return H XOR (H >> 16). All arithmetic uses unsigned 32-bit wraparound and
 * logical shifts. Reversing endpoints preserves the result; no fixed encoded
 * endpoint erases variation in the other. Encoding and worker reduction still
 * permit collisions. The generic parser preserves the full64
 * helper's SCTP, IPv6-folding and fragment-identity classification boundaries. */
bool deviceFlowWorkerHash(const uint8_t *packet, uint32_t length, uint32_t *out_hash);

/* Device policy: valid IPv4 fragments always use address/protocol fallback;
 * ordinary TCP/UDP use the first four payload bytes when present. Opaque IPv4
 * uses prefix, peer, or returns false for spread. IPv6 retains exact-length plain
 * TCP/UDP with four transport bytes. False leaves *out_hash unchanged. */
bool deviceReceiveWorkerHash(const uint8_t *packet, uint32_t length, device_opaque_flow_mode_t mode,
                             uint32_t *out_hash);

/* Endpoint words are ports or opaque prefix words. Zero words construct the
 * address/protocol fallback. fragment_key is zero except for generic software
 * fragment identity (0x10000 | IPv4 ID). */
uint32_t deviceFlowWorkerHashTuple(uint32_t src, uint16_t src_word, uint32_t dst, uint16_t dst_word, uint8_t protocol,
                                   uint32_t fragment_key);
