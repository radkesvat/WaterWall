#pragma once

/*
 * Declares packet-oriented tunnel defaults used by L3/L4 style nodes.
 */

#include "cJSON.h"
#include "devices/device_fragment_policy.h"
#include "devices/device_opaque_flow_mode.h"
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

/* Exclusive startup only. The device initiator must establish its private
 * checksum mode before publishing the pair, and before starting producers. */
bool packettunnelTrustedChecksumPairEligible(const tunnel_t *source, const tunnel_t *consumer);
void packettunnelActivateTrustedChecksumPair(tunnel_t *source, tunnel_t *consumer);
bool packettunnelTrustedChecksumsActive(const tunnel_t *t);
/* Direct-pair receive trust, independent of negotiated transmit offload. */
void packettunnelActivateTrustedReceiveChecksumPair(tunnel_t *source, tunnel_t *consumer);
bool packettunnelTrustedReceiveChecksumsActive(const tunnel_t *t);

/* Exact owner-worker packet edge to an immediate certified sink. Static topology
 * and capability keep dispatch policy fixed throughout the route lifetime. */
bool packettunnelCanEnqueueDownstreamInline(const tunnel_t *producer, const line_t *packet_line);

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
 * @brief Consume an ordinary packet buffer's checksum-recalculation request and perform it.
 *
 * The request is cleared before the attempt rather than after a successful one.
 * This terminal boundary discards packets when repair is refused. Transforms
 * that can decline and forward unchanged must preserve intent on refusal.
 *
 * @param buf Ordinary packet carrying the request; the caller keeps ownership either way.
 * Structural IPv4 validation is unconditional, including when no checksum work
 * was requested. The IPv4 total length must exactly match the sbuf length.
 *
 * @return true when the packet is structurally valid and either nothing was
 *         requested or recalculation succeeded. false for malformed input,
 *         IPv6, trailing bytes, or a recalculation failure.
 */
bool packettunnelConsumeChecksumRequest(sbuf_t *buf);

/**
 * Take and clear the checksum request carried by an ordinary packet buffer.
 *
 * The returned intent may accompany a byte copy owned by the caller. It is a
 * repair request, not checksum assurance or hardware offload metadata.
 */
bool packettunnelTakeChecksumRequest(sbuf_t *buf);

/**
 * Validate normalized mutable IPv4 bytes and apply a previously taken request.
 *
 * Structural validation is performed even when @p requested is false. A
 * fragmented packet can have its IPv4 header checksum repaired, but the helper
 * deliberately does not synthesize a whole-datagram transport checksum from an
 * individual fragment.
 */
bool packettunnelFinalizeChecksumRequest(bool requested, uint8_t *packet, uint32_t length);

/* Defaults to reassemble when omitted; explicit invalid values are rejected. */
bool packettunnelReadFragmentPolicy(const cJSON *settings, device_fragment_policy_t *policy);

/* Defaults to prefix when omitted; explicit null and all values other than the
 * exact strings prefix, peer, spread and auto are rejected. */
bool packettunnelReadOpaqueFlowMode(const cJSON *settings, device_opaque_flow_mode_t *mode);

/* Exclusive startup, after lifecycle-anchor binding. Inspect only the physical
 * publication neighbour: upstream PingServer and downstream PingClient decode.
 * Explicit modes are unchanged. The returned mode is always effective, never auto.
 * The reason points to static diagnostic text. */
device_opaque_flow_mode_t packettunnelResolveOpaqueFlowMode(tunnel_t *t, device_opaque_flow_mode_t requested,
                                                            const char **reason);
