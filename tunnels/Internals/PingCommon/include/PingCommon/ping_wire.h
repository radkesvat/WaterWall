#ifndef PING_COMMON_PING_WIRE_H_
#define PING_COMMON_PING_WIRE_H_

/*
 * The Ping codec inserts Echo framing into an existing IPv4 packet.  It owns the
 * deterministic packet mechanics shared by PingClient and PingServer; those
 * nodes retain callback direction, buffer ownership, and configuration work.
 */

#include "wwapi.h"

#include "lwip/prot/icmp.h"
#include "lwip/prot/ip4.h"

enum
{
    kPingWireIpv4HeaderLength         = IP_HLEN,
    kPingWireIcmpHeaderLength         = sizeof(struct icmp_echo_hdr),
    kPingWireEncapsulationOverhead    = kPingWireIcmpHeaderLength + 1,
    kPingWireMaxInnerPacketLength     = kMaxAllowedPacketLength - kPingWireEncapsulationOverhead,
    kPingWirePayloadDigestLength      = 16,
    kPingWireOutstandingCapacity      = 1024,
    kPingWireReplayCapacity           = 1024,
    kPingWireReplyIdlePerturbationMs  = 1000,
    kPingWireReplyPerturbationMaximum = 31,
};

_Static_assert(kPingWireIpv4HeaderLength == 20, "IPv4 minimum header length changed unexpectedly");
_Static_assert(kPingWireEncapsulationOverhead == 9, "Ping padding contract changed unexpectedly");
_Static_assert(kPingWireOutstandingCapacity < UINT16_MAX,
               "Ping outstanding capacity must remain below one 16-bit sequence space");

typedef struct ping_wire_config_s
{
    uint16_t identifier;
} ping_wire_config_t;

typedef struct ping_wire_envelope_s
{
    /* Static diagnostic text on a rejected carrier; NULL on successful classification. */
    const char    *error_reason;
    const uint8_t *icmp_payload;
    uint32_t       source_ipv4;
    uint32_t       destination_ipv4;
    uint16_t       total_length;
    uint16_t       icmp_payload_length;
    uint16_t       ip_header_length;
    uint16_t       echo_offset; /* Distinct from IPv4 IHL when an IPv6 base header is present. */
    uint16_t       native_body_length;
    uint8_t        native_protocol;
    uint16_t       identifier;
    uint16_t       sequence;
    uint8_t        tos;
    uint8_t        ttl;
    uint8_t        type;
    uint8_t        code;
} ping_wire_envelope_t;

typedef enum ping_wire_inbound_kind_e
{
    /* Not a complete valid IPv4 packet, or a complete carrier with a bad checksum. */
    kPingWireInboundMalformed = 0,
    /* A valid IPv4 packet with another visible protocol. */
    kPingWireInboundUnrelated,
    /* Selected as carrier traffic, but not a valid Echo envelope. */
    kPingWireInboundInvalidCarrier,
    kPingWireInboundEchoRequest,
    kPingWireInboundEchoReply,
} ping_wire_inbound_kind_t;

typedef struct ping_wire_outstanding_entry_s
{
    uint16_t identifier;
    uint16_t sequence;
    uint16_t payload_length;
    bool     occupied;
    uint8_t  payload_digest[kPingWirePayloadDigestLength];
} ping_wire_outstanding_entry_t;

typedef struct ping_wire_outstanding_table_s
{
    ping_wire_outstanding_entry_t entries[kPingWireOutstandingCapacity];
    uint32_t                      replacement_index;
} ping_wire_outstanding_table_t;

typedef struct ping_wire_replay_entry_s
{
    uint16_t identifier;
    uint16_t sequence;
    uint16_t payload_length;
    bool     occupied;
    uint8_t  payload_digest[kPingWirePayloadDigestLength];
} ping_wire_replay_entry_t;

typedef struct ping_wire_replay_table_s
{
    ping_wire_replay_entry_t entries[kPingWireReplayCapacity];
    uint32_t                 replacement_index;
} ping_wire_replay_table_t;

typedef struct ping_wire_tracker_s
{
    ping_wire_outstanding_table_t outstanding;
    ping_wire_replay_table_t      replay;
    wmutex_t                      outstanding_mutex;
    wmutex_t                      replay_mutex;
    bool                          outstanding_mutex_initialized;
    bool                          replay_mutex_initialized;
} ping_wire_tracker_t;

typedef enum ping_wire_replay_result_e
{
    kPingWireReplayNew = 0,
    kPingWireReplayDuplicate,
    kPingWireReplayError,
} ping_wire_replay_result_t;

/*
 * This is an observable approximation of Linux's tuple-scoped IPv4 ID
 * selection.  It is intentionally not a copy of kernel-global state.
 */
typedef struct ping_wire_reply_id_generator_s
{
    atomic_u32_t  visible_counter;
    atomic_u32_t  random_state;
    atomic_ullong last_reply_ms;
} ping_wire_reply_id_generator_t;

/* Validate exact IPv4 geometry; codec admission separately rejects fragments. */
WW_EXPORT bool pingwireIsExactIpv4Packet(const uint8_t *packet, uint32_t length);

/* Validate exact IPv4 framing; return a static failure reason or NULL on success. */
WW_EXPORT const char *pingwireIpv4PacketError(const uint8_t *packet, uint32_t length);

/* The same validation, also filling the view of an accepted packet. */
WW_EXPORT const char *pingwireIpv4PacketErrorWithView(const uint8_t *packet, uint32_t length, ipv4_packet_view_t *view);

/* Resolve an explicit identifier or accept one injected random candidate. */
WW_EXPORT bool pingwireSelectIdentifier(bool random, uint16_t configured, uint16_t random_candidate,
                                        uint16_t *identifier_out);

/* Shared native geometry, including permitted UDP padding and opaque protocols. */
WW_EXPORT bool pingwireNativeShape(const uint8_t *body, uint16_t length, uint8_t protocol);

/* Parse the selected visible protocol; the chain owns address/peer selection. */
WW_EXPORT ping_wire_inbound_kind_t pingwireParseInbound(const uint8_t *packet, uint32_t length,
                                                        const ping_wire_config_t *config,
                                                        ping_wire_envelope_t     *envelope_out);

/* Pure admission check, then native repair before a node reserves sequence state. */
WW_EXPORT const char *pingwireEchoRequestError(const sbuf_t *buf);
WW_EXPORT const char *pingwirePrepareEchoRequest(sbuf_t *buf);

/* Insert a fresh Echo header and final protocol trailer into one native packet. */
WW_EXPORT bool pingwireEchoRequestPreflight(const sbuf_t *buf);
WW_EXPORT bool pingwireBuildEchoRequest(sbuf_t *buf, const ping_wire_config_t *config, uint16_t sequence);

/* Convert a cloned, validated Echo Request envelope into its exact type-0 reply. */
WW_EXPORT bool pingwireBuildEchoReply(sbuf_t *buf, const ping_wire_config_t *config,
                                      const ping_wire_envelope_t *request, uint16_t ipv4_identification);

/* Remove Echo framing/trailer and restore native checksum address contributions. */
WW_EXPORT bool pingwireStripEchoRequest(sbuf_t *buf, const ping_wire_envelope_t *request);

/* Shared Ping/Ping6 Echo mechanics. The checksum seed includes any pseudo-header. */
WW_EXPORT ping_wire_inbound_kind_t pingwireParseEcho(const uint8_t *packet, uint32_t length, uint8_t protocol,
                                                     uint8_t request_type, uint8_t reply_type, uint32_t checksum_seed,
                                                     ping_wire_envelope_t *envelope_out);
WW_EXPORT bool pingwireBuildRequest(sbuf_t *buf, uint16_t identifier, uint16_t sequence, uint8_t protocol,
                                    uint8_t request_type, uint32_t checksum_seed);
WW_EXPORT bool pingwireBuildReply(sbuf_t *buf, const ping_wire_envelope_t *request, uint16_t ipv4_identification,
                                  uint8_t protocol, uint8_t request_type, uint8_t reply_type, uint32_t checksum_seed);
WW_EXPORT bool pingwireStripRequest(sbuf_t *buf, const ping_wire_envelope_t *request, uint8_t request_type);
WW_EXPORT bool pingwireRecalculateEchoChecksums(sbuf_t *buf, uint8_t protocol, uint32_t checksum_seed);
WW_EXPORT bool pingwireRecalculateCarrierChecksums(sbuf_t *buf);

/* Construct/destroy one node-wide synchronized bounded correlation tracker. */
WW_EXPORT ping_wire_tracker_t *pingwireTrackerCreate(void);
WW_EXPORT void                 pingwireTrackerDestroy(ping_wire_tracker_t *tracker);

/* Register a locally emitted request before it is forwarded to a peer. */
WW_EXPORT bool pingwireOutstandingRecord(ping_wire_tracker_t *tracker,
                                         const uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE], uint16_t identifier,
                                         uint16_t sequence, const uint8_t *payload, uint16_t payload_length);

/* Consume only an exact, correlated Echo Reply of the caller's wire type. */
WW_EXPORT bool pingwireOutstandingConsumeForType(ping_wire_tracker_t        *tracker,
                                                 const uint8_t               digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                                 const ping_wire_envelope_t *reply, uint8_t expected_type);
WW_EXPORT bool pingwireOutstandingConsume(ping_wire_tracker_t        *tracker,
                                          const uint8_t               digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                          const ping_wire_envelope_t *reply);

/* Record a peer request of the caller's wire type; duplicates remain eligible for a reply. */
WW_EXPORT ping_wire_replay_result_t pingwireReplayMarkForType(ping_wire_tracker_t *tracker,
                                                              const uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                                              const ping_wire_envelope_t *request,
                                                              uint8_t                     expected_type);
WW_EXPORT ping_wire_replay_result_t pingwireReplayMark(ping_wire_tracker_t *tracker,
                                                       const uint8_t        digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                                       const ping_wire_envelope_t *request);

/* Initialize and advance the Linux-like reply-side IPv4-ID approximation. */
WW_EXPORT void     pingwireReplyIdGeneratorInitialize(ping_wire_reply_id_generator_t *generator, uint32_t seed,
                                                      uint64_t now_ms);
WW_EXPORT uint16_t pingwireReplyIdGeneratorNextAt(ping_wire_reply_id_generator_t *generator, uint64_t now_ms,
                                                  uint32_t idle_perturbation);
WW_EXPORT uint16_t pingwireReplyIdGeneratorNext(ping_wire_reply_id_generator_t *generator, uint64_t now_ms);

#endif /* PING_COMMON_PING_WIRE_H_ */
