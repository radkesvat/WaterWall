#pragma once

/*
 * Flow-affine worker selection and bucketed dispatch for packet-device readers.
 */

#include "devices/device_reader_session.h"

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
 * protocol shares a flow.
 */
bool deviceFlowAffinityHash(const uint8_t *packet, uint32_t length, uint64_t *out_hash);

/*
 * Selects the same worker for both directions of a parseable IP flow. This is
 * exactly deviceFlowAffinityHash() reduced modulo the worker count. Returns
 * false for malformed or unsupported packets so callers can retain their
 * round-robin fallback.
 */
bool deviceFlowAffineWID(const uint8_t *packet, uint32_t length, wid_t *out_wid);

/*
 * Takes ownership of every buffer and posts one batch per selected worker.
 * Parseable IP packets are flow-affine; other packets retain round-robin
 * distribution.
 */
/* Returns false only for a fatal partial-fragment publication failure. */
bool deviceFlowAffinityPostBatch(device_reader_session_t *session, sbuf_t **bufs, unsigned int count);
