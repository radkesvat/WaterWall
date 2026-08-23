#ifndef PING_COMMON_PING_WIRE_H_
#define PING_COMMON_PING_WIRE_H_

/*
 * Ping wire v2 is deliberately a narrow IPv4/ICMP Echo codec.  It owns the
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
    kPingWireEncapsulationOverhead    = kPingWireIpv4HeaderLength + kPingWireIcmpHeaderLength,
    kPingWireMaxInnerPacketLength     = kMaxAllowedPacketLength - kPingWireEncapsulationOverhead,
    kPingWirePayloadDigestLength      = 16,
    kPingWireOutstandingCapacity      = 1024,
    kPingWireReplayCapacity           = 1024,
    kPingWireReplyIdlePerturbationMs  = 1000,
    kPingWireReplyPerturbationMaximum = 31,
};

_Static_assert(kPingWireIpv4HeaderLength == 20, "Ping wire v2 requires a 20-byte IPv4 header");
_Static_assert(kPingWireEncapsulationOverhead == 28, "Ping wire v2 padding contract changed unexpectedly");
_Static_assert(kPingWireOutstandingCapacity < UINT16_MAX,
               "Ping outstanding capacity must remain below one 16-bit sequence space");

typedef struct ping_wire_config_s
{
    uint32_t local_ipv4;
    uint32_t peer_ipv4;
    uint16_t identifier;
    uint8_t  ttl;
    uint8_t  tos;
} ping_wire_config_t;

typedef struct ping_wire_envelope_s
{
    const uint8_t *icmp_payload;
    const uint8_t *inner_ipv4;
    uint32_t       source_ipv4;
    uint32_t       destination_ipv4;
    uint16_t       total_length;
    uint16_t       icmp_payload_length;
    uint16_t       inner_ipv4_length;
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
    /* A valid IPv4 packet that is not addressed to this Ping endpoint. */
    kPingWireInboundUnrelated,
    /* Addressed as carrier traffic, but not a valid v2 Echo envelope. */
    kPingWireInboundInvalidCarrier,
    kPingWireInboundEchoRequest,
    kPingWireInboundEchoReply,
} ping_wire_inbound_kind_t;

typedef struct ping_wire_outstanding_entry_s
{
    uint32_t source_ipv4;
    uint32_t destination_ipv4;
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
    atomic_uint   visible_counter;
    atomic_uint   random_state;
    atomic_ullong last_reply_ms;
} ping_wire_reply_id_generator_t;

/* Validate one exact IPv4 packet (including an inner fragment). */
WW_EXPORT bool pingwireIsExactIpv4Packet(const uint8_t *packet, uint32_t length);

/* Resolve an explicit identifier or accept one injected random candidate. */
WW_EXPORT bool pingwireSelectIdentifier(bool random, uint16_t configured, uint16_t random_candidate,
                                        uint16_t *identifier_out);

/* Parse one inbound carrier relative to the local endpoint's configured tuple. */
WW_EXPORT ping_wire_inbound_kind_t pingwireParseInbound(const uint8_t *packet, uint32_t length,
                                                        const ping_wire_config_t *config,
                                                        ping_wire_envelope_t     *envelope_out);

/* Build a fresh type-8 Echo Request around one exact inner IPv4 packet. */
WW_EXPORT bool pingwireEchoRequestPreflight(const sbuf_t *buf);
WW_EXPORT bool pingwireBuildEchoRequest(sbuf_t *buf, const ping_wire_config_t *config, uint16_t sequence);

/* Convert a cloned, validated Echo Request envelope into its exact type-0 reply. */
WW_EXPORT bool pingwireBuildEchoReply(sbuf_t *buf, const ping_wire_config_t *config,
                                      const ping_wire_envelope_t *request, uint16_t ipv4_identification);

/* Strip a validated Echo Request's fixed IPv4+ICMP carrier envelope in place. */
WW_EXPORT bool pingwireStripEchoRequest(sbuf_t *buf, const ping_wire_envelope_t *request);

/* Construct/destroy one node-wide synchronized bounded correlation tracker. */
WW_EXPORT ping_wire_tracker_t *pingwireTrackerCreate(void);
WW_EXPORT void                 pingwireTrackerDestroy(ping_wire_tracker_t *tracker);

/* Register a locally emitted request before it is forwarded to a peer. */
WW_EXPORT bool pingwireOutstandingRecord(ping_wire_tracker_t *tracker,
                                         const uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE], uint16_t identifier,
                                         uint16_t sequence, uint32_t reply_source_ipv4, uint32_t reply_destination_ipv4,
                                         const uint8_t *payload, uint16_t payload_length);

/* Consume only an exact, correlated Echo Reply. */
WW_EXPORT bool pingwireOutstandingConsume(ping_wire_tracker_t        *tracker,
                                          const uint8_t               digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                          const ping_wire_envelope_t *reply);

/* Record a peer request once; duplicate requests remain eligible for a reply. */
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
