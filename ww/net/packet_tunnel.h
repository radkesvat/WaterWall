#pragma once

/*
 * Declares packet-oriented tunnel defaults used by L3/L4 style nodes.
 */

#include "tunnel.h"

/**
 * @brief Create a packet tunnel with standard lifecycle pass-through routines and mandatory payload overrides.
 *
 * @param node Owner node.
 * @param tstate_size Tunnel-local state size.
 * @param lstate_size Must be zero for packet tunnels.
 * @return tunnel_t* Created packet tunnel.
 */
tunnel_t *packettunnelCreate(node_t *node, size_t tstate_size, size_t lstate_size);

typedef enum packet_lifecycle_anchor_direction_e
{
    kPacketLifecycleAnchorPublishUpstream = 0,
    kPacketLifecycleAnchorPublishDownstream
} packet_lifecycle_anchor_direction_t;

typedef struct packet_lifecycle_anchor_s
{
    const char                         *name;
    tunnel_t                           *publication_tunnel;
    TunnelFlowRoutinePayload            publication_callback;
    packet_lifecycle_anchor_direction_t direction;
} packet_lifecycle_anchor_t;

/**
 * Configure an L3 device anchor with zero line state and fatal Finish hooks.
 * The configured tunnel state must begin with packet_lifecycle_anchor_t at
 * offset zero; the lifecycle helpers treat it as a state prefix.
 */
bool packettunnelConfigureLifecycleAnchor(tunnel_t *t, const char *name, TunnelFlowRoutinePayload write_payload,
                                          packet_lifecycle_anchor_direction_t direction);

/** Resolve the configured publication neighbour after chaining. */
bool packettunnelLifecycleAnchorBind(tunnel_t *t);

/** Publish one device packet and enforce packet-line survival. */
void packettunnelLifecycleAnchorPublish(tunnel_t *t, line_t *packet_line, sbuf_t *buf);

/**
 * @brief Consume a packet line's checksum-recalculation request and perform it.
 *
 * The request is cleared before the attempt rather than after a successful one.
 * A worker's packet line is persistent, so a refusal that left the flag set
 * would make the next, unrelated packet on that line be recalculated too.
 *
 * @param line Packet line carrying the request.
 * @param buf Packet the request applies to; the caller keeps ownership either way.
 * Structural IPv4 validation is unconditional, including when no checksum work
 * was requested. The IPv4 total length must exactly match the sbuf length.
 *
 * @return true when the packet is structurally valid and either nothing was
 *         requested or recalculation succeeded. false for malformed input,
 *         IPv6, trailing bytes, or a recalculation failure.
 */
bool packettunnelConsumeChecksumRequest(line_t *line, sbuf_t *buf);

/**
 * Take and clear the one-packet checksum request carried by a packet line.
 *
 * This operation must happen at callback entry, before any path can reject the
 * packet. Packet lines are persistent worker-local objects, so leaving the bit
 * set would apply one packet's request to unrelated traffic.
 */
bool packettunnelTakeChecksumRequest(line_t *line);

/**
 * Validate normalized mutable IPv4 bytes and apply a previously taken request.
 *
 * Structural validation is performed even when @p requested is false. A
 * fragmented packet can have its IPv4 header checksum repaired, but the helper
 * deliberately does not synthesize a whole-datagram transport checksum from an
 * individual fragment.
 */
bool packettunnelFinalizeChecksumRequest(bool requested, uint8_t *packet, uint32_t length);
