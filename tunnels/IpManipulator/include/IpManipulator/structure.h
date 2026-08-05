#pragma once

#include "wwapi.h"

#include "flow_table.h"
#include "ipv4_packet_view.h"

/*
 * True when a packet line may join a retained group owned by @p owner_wid.
 * An invalid owner means that the group is empty and the caller must stamp the
 * line's worker before retaining it.
 */
static inline bool ipmanipulatorPacketJoinsOwner(wid_t owner_wid, const line_t *l)
{
    return owner_wid == kInvalidWID || (l != NULL && lineGetWID(l) == owner_wid);
}

enum tcp_bit_action_dynamic_value
{
    kDvsNoAction = kDvsEmpty,
    kDvsOff      = kDvsFirstOption,
    kDvsOn,
    kDvsToggle,
    kDvsPacketCwr,
    kDvsPacketEce,
    kDvsPacketUrg,
    kDvsPacketAck,
    kDvsPacketPsh,
    kDvsPacketRst,
    kDvsPacketSyn,
    kDvsPacketFin
};

/*
 * One shared definition of a flow-opening TCP SYN for every stateful SNI
 * tracker. A flow may only be opened by a payload-free SYN that carries no
 * ACK/FIN/RST and no unexpected control flag. ECE and CWR are allowed so an
 * ECN negotiation SYN still starts tracking; TCP Fast Open SYN data stays
 * unsupported and fails open without creating trick state.
 */
static inline bool ipmanipulatorIsFlowOpeningSyn(uint8_t tcp_flags, uint32_t tcp_payload_len)
{
    return ipv4packetviewTcpFlagsAreOpeningSyn(tcp_flags, tcp_payload_len);
}

typedef struct sni_match_s
{
    uint16_t ip_total_len;
    uint16_t tls_record_len;
    uint32_t client_hello_len;
    bool     has_tls13_psk_binder;
    uint16_t extensions_len;
    uint16_t server_name_list_len;
    uint16_t server_name_ext_len;
    uint16_t sni_name_len;

    uint32_t sni_name_offset;
    uint32_t sni_name_len_field_offset;
    uint32_t extensions_len_field_offset;
    uint32_t server_name_list_len_field_offset;
    uint32_t server_name_ext_len_field_offset;
    uint32_t tls_record_len_field_offset;
    uint32_t client_hello_len_field_offset;
} sni_match_t;

typedef enum ipmanipulator_tls_capture_kind_e
{
    kIpManipulatorTlsCaptureKindNone = 0,
    kIpManipulatorTlsCaptureKindFirstSni,
    kIpManipulatorTlsCaptureKindSmuggleSni,
    kIpManipulatorTlsCaptureKindEchSni
} ipmanipulator_tls_capture_kind_e;

typedef enum ipmanipulator_tls_capture_status_e
{
    kIpManipulatorTlsCaptureStatusMiss = 0,
    kIpManipulatorTlsCaptureStatusPending,
    kIpManipulatorTlsCaptureStatusReady,
    kIpManipulatorTlsCaptureStatusBypassed
} ipmanipulator_tls_capture_status_e;

typedef enum ipmanipulator_tls_clienthello_start_status_e
{
    kIpManipulatorTlsClientHelloStartMiss = 0,
    kIpManipulatorTlsClientHelloStartPartial,
    kIpManipulatorTlsClientHelloStartComplete,
    kIpManipulatorTlsClientHelloStartFragmented,
    kIpManipulatorTlsClientHelloStartUnsupported
} ipmanipulator_tls_clienthello_start_status_e;

enum
{
    kSniBlenderTrickMinPacketsCount        = 2,
    kSniBlenderTrickMaxPacketsCount        = 16,
    kPacketDuplicateTrickMaxCount          = 16,
    kFirstSniTrickMaxCount                 = 16,
    kIpManipulatorTlsCaptureSlotsPerWorker = 16,
    kIpManipulatorTlsCaptureMaxPackets     = 16,
    kIpManipulatorDelayBarrierMaxPackets   = 16,
    kIpManipulatorDelayBarrierMaxBytes     = 256U * 1024U,

    /*
     * A TLS host_name is carried in a 16-bit vector on the wire, but the paired
     * TlsClient refuses anything longer than 255 bytes. IpManipulator must
     * enforce the same boundary so an accepted configuration can always be
     * embedded in the crafted handshakes.
     */
    kIpManipulatorMaxTlsHostNameLen = 255
};

typedef enum ipmanipulator_config_validation_e
{
    kIpManipulatorConfigValid = 0,
    /*
     * An upstream TCP-bit action runs before every stateful SNI state machine,
     * while their generated and replayed packets do not consistently re-enter
     * TCP-bit processing.
     */
    kIpManipulatorConfigRejectUpstreamTcpBitWithStatefulSni,
    /*
     * preserve-tcp-bitflags appends a metadata byte upstream; SNI Blender then
     * fragments the packet and the peer restoration path skips fragments.
     */
    kIpManipulatorConfigRejectPreservedTcpBitWithSniBlender,
    /*
     * Two stateful SNI state machines in one instance would each try to own the
     * same flow's ClientHello and emit their own transcript for it.
     */
    kIpManipulatorConfigRejectMultipleStatefulSni,
    /*
     * A stateful SNI trick emits its crafted packets through the direct egress
     * helper, so they never reach a later SNI Blender stage of the same
     * instance. Chain a second IpManipulator node instead.
     */
    kIpManipulatorConfigRejectSniBlenderWithStatefulSni,
    /* Same reasoning as above for the final packet-duplication stage. */
    kIpManipulatorConfigRejectPacketDuplicateWithStatefulSni,
    /* Port ghost intentionally skips IPv4 fragments, which SNI Blender emits. */
    kIpManipulatorConfigRejectSniBlenderWithPortGhost
} ipmanipulator_config_validation_e;

typedef struct ipmanipulator_captured_packet_s
{
    line_t *line;
    sbuf_t *buf;
} ipmanipulator_captured_packet_t;

typedef enum ipmanipulator_delay_barrier_kind_e
{
    kIpManipulatorDelayBarrierFirstSni = 0,
    kIpManipulatorDelayBarrierSmuggleSni,
    kIpManipulatorDelayBarrierOverlapSni
} ipmanipulator_delay_barrier_kind_e;

/*
 * One transcript output owned by the per-flow ordered delay scheduler. The
 * scheduler retains the line and invokes send only after due_ms. Entries must
 * be installed in their logical wire order with nondecreasing deadlines.
 */
typedef struct ipmanipulator_ordered_output_s
{
    line_t           *line;
    sbuf_t           *buf;
    LineTaskFnWithBuf send;
    uint64_t          due_ms;
} ipmanipulator_ordered_output_t;

/*
 * A fixed-size per-flow FIFO used only while a stateful SNI transcript has
 * delayed output pending. Each retained line is locked until its packet is
 * forwarded or recycled, so a normal-line test fixture is as safe as the
 * persistent worker packet line used in production.
 */
typedef struct ipmanipulator_delay_barrier_s
{
    uint64_t                        generation;
    uint64_t                        deadline_ms;
    uint32_t                        retained_bytes;
    wid_t                           owner_wid;
    uint8_t                         count;
    bool                            timer_armed;
    bool                            remove_after_release;
    ipmanipulator_ordered_output_t *ordered_outputs;
    uint32_t                        ordered_outputs_count;
    uint32_t                        next_ordered_output;
    ipmanipulator_captured_packet_t packets[kIpManipulatorDelayBarrierMaxPackets];
} ipmanipulator_delay_barrier_t;

typedef struct ipmanipulator_delay_batch_s
{
    uint8_t                         count;
    ipmanipulator_ordered_output_t *ordered_outputs;
    uint32_t                        ordered_outputs_count;
    uint32_t                        next_ordered_output;
    ipmanipulator_captured_packet_t packets[kIpManipulatorDelayBarrierMaxPackets];
} ipmanipulator_delay_batch_t;

typedef struct ipmanipulator_tls_capture_timeout_msg_s
{
    uint32_t slot_index;
    uint32_t generation;
} ipmanipulator_tls_capture_timeout_msg_t;

typedef struct ipmanipulator_tls_capture_slot_s
{
    sbuf_t  *assembled_packet;
    uint64_t last_update_ms;
    /*
     * Flow generation that owns this capture. First-SNI and Smuggle-SNI leave
     * it zero; ECH copies the generation from its bounded flow entry so a
     * timeout, eviction, close or tuple reuse can never touch a replacement.
     */
    uint64_t owner_generation;
    /* Every retained packet in this slot must belong to this worker. */
    wid_t                            owner_wid;
    uint32_t                         generation;
    uint32_t                         next_seq;
    uint32_t                         tls_record_total_len;
    uint32_t                         tls_record_captured_len;
    uint32_t                         captured_payload_len;
    uint32_t                         src_addr;
    uint32_t                         dst_addr;
    uint16_t                         src_port;
    uint16_t                         dst_port;
    uint16_t                         ip_header_len;
    uint16_t                         tcp_header_len;
    uint16_t                         headers_len;
    uint8_t                          captured_packets_count;
    ipmanipulator_tls_capture_kind_e kind;
    bool                             active;
    ipmanipulator_captured_packet_t  captured_packets[kIpManipulatorTlsCaptureMaxPackets];
} ipmanipulator_tls_capture_slot_t;

typedef struct ipmanipulator_tls_prestart_slot_s
{
    uint64_t last_update_ms;
    /* Every retained packet in this slot must belong to this worker. */
    wid_t                            owner_wid;
    uint32_t                         src_addr;
    uint32_t                         dst_addr;
    uint16_t                         src_port;
    uint16_t                         dst_port;
    uint32_t                         generation;
    uint8_t                          captured_packets_count;
    ipmanipulator_tls_capture_kind_e kind;
    bool                             active;
    ipmanipulator_captured_packet_t  captured_packets[kIpManipulatorTlsCaptureMaxPackets];
} ipmanipulator_tls_prestart_slot_t;

typedef enum ipmanipulator_smuggle_flow_phase_e
{
    kIpManipulatorSmuggleFlowPhaseWarmup = 0,
    kIpManipulatorSmuggleFlowPhaseCapture,
    kIpManipulatorSmuggleFlowPhasePassthrough
} ipmanipulator_smuggle_flow_phase_e;

/*
 * Every stateful trick record below lives inside a bounded flow-table entry.
 * Membership in the table is what makes a flow active, so the records carry no
 * "active" flag and a record pointer is only valid while its shard is locked.
 * The client-to-server orientation is kept in the record because transcript
 * logic needs it; lookup always goes through the normalized table key.
 */
typedef struct ipmanipulator_smuggle_flow_s
{
    uint64_t                           created_ms;
    uint64_t                           last_activity_ms;
    uint64_t                           delay_window_until_ms;
    uint32_t                           src_addr;
    uint32_t                           dst_addr;
    uint16_t                           src_port;
    uint16_t                           dst_port;
    uint8_t                            warmup_packets_seen;
    ipmanipulator_smuggle_flow_phase_e phase;
    ipmanipulator_delay_barrier_t      delay_barrier;
} ipmanipulator_smuggle_flow_t;

typedef struct ipmanipulator_firstsni_flow_s
{
    uint64_t                      created_ms;
    uint64_t                      last_activity_ms;
    uint64_t                      delay_window_until_ms;
    uint32_t                      src_addr;
    uint32_t                      dst_addr;
    uint16_t                      src_port;
    uint16_t                      dst_port;
    ipmanipulator_delay_barrier_t delay_barrier;
} ipmanipulator_firstsni_flow_t;

typedef enum ipmanipulator_overlap_flow_phase_e
{
    kIpManipulatorOverlapFlowPhaseWarmup = 0,
    kIpManipulatorOverlapFlowPhaseHoldThird,
    kIpManipulatorOverlapFlowPhasePassthrough,
    kIpManipulatorOverlapFlowPhaseBlocked
} ipmanipulator_overlap_flow_phase_e;

typedef struct ipmanipulator_overlap_flow_s
{
    uint64_t                           created_ms;
    uint64_t                           last_activity_ms;
    uint64_t                           delay_window_until_ms;
    uint64_t                           hold_generation; /* Current HoldThird fail-open timer identity. */
    uint32_t                           src_addr;
    uint32_t                           dst_addr;
    uint16_t                           src_port;
    uint16_t                           dst_port;
    uint8_t                            warmup_packets_seen;
    ipmanipulator_overlap_flow_phase_e phase;
    bool                               hold_timer_armed;
    wid_t                              held_wid;
    ipmanipulator_captured_packet_t    held_packet;
    ipmanipulator_delay_barrier_t      delay_barrier;
} ipmanipulator_overlap_flow_t;

typedef enum ipmanipulator_synfin_flow_phase_e
{
    kIpManipulatorSynfinFlowPhaseWarmup = 0,
    kIpManipulatorSynfinFlowPhaseHoldThird,
    kIpManipulatorSynfinFlowPhasePassthrough,
    kIpManipulatorSynfinFlowPhaseBlocked
} ipmanipulator_synfin_flow_phase_e;

typedef struct ipmanipulator_synfin_flow_s
{
    uint64_t                          created_ms;
    uint64_t                          last_activity_ms;
    uint64_t                          hold_generation; /* Current HoldThird fail-open timer identity. */
    uint32_t                          src_addr;
    uint32_t                          dst_addr;
    uint16_t                          src_port;
    uint16_t                          dst_port;
    uint8_t                           warmup_packets_seen;
    ipmanipulator_synfin_flow_phase_e phase;
    bool                              hold_timer_armed;
    wid_t                             held_wid;
    ipmanipulator_captured_packet_t   held_packet;
    sbuf_t                           *syn_packet_template;
} ipmanipulator_synfin_flow_t;

typedef enum ipmanipulator_echsni_flow_phase_e
{
    /* No recognizable ClientHello has started yet on this generation. */
    kIpManipulatorEchSniFlowPhaseAwaitingClientHello = 0,
    /* A ClientHello record is being assembled by the shared capture helper. */
    kIpManipulatorEchSniFlowPhaseCapturing,
    /* The fake inner packet was emitted; originals are waiting on their timers. */
    kIpManipulatorEchSniFlowPhaseReleasing,
    /* This generation is done inspecting; later packets pass unchanged. */
    kIpManipulatorEchSniFlowPhasePassthrough,
    /* Terminal reject: the flow may not proceed with the crafted transcript. */
    kIpManipulatorEchSniFlowPhaseBlocked
} ipmanipulator_echsni_flow_phase_e;

typedef struct ipmanipulator_echsni_flow_s
{
    uint64_t created_ms;
    uint64_t last_activity_ms;
    uint64_t shard1_release_at_ms;
    uint64_t shard2_release_at_ms;
    uint64_t generation;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    wid_t    owner_wid;
    /* Bounded batch of unmodified originals owned by this flow generation. */
    uint8_t                           pending_original_count;
    uint8_t                           next_release_index;
    ipmanipulator_echsni_flow_phase_e phase;
    ipmanipulator_captured_packet_t   pending_original_packets[kIpManipulatorTlsCaptureMaxPackets];
} ipmanipulator_echsni_flow_t;

typedef enum ipmanipulator_smuggle_fin_queue_direction_e
{
    kIpManipulatorSmuggleFinQueueDirectionUpstream = 0,
    kIpManipulatorSmuggleFinQueueDirectionDownstream
} ipmanipulator_smuggle_fin_queue_direction_e;

typedef struct ipmanipulator_smuggle_fin_queued_packet_s
{
    sbuf_t                                     *buf;
    ipmanipulator_smuggle_fin_queue_direction_e direction;
    bool                                        recalculate_checksum;
} ipmanipulator_smuggle_fin_queued_packet_t;

typedef struct ipmanipulator_smuggle_fin_flow_s
{
    uint64_t                                   last_activity_ms;
    uint64_t                                   paused_at_ms;
    uint32_t                                   src_addr;
    uint32_t                                   dst_addr;
    uint32_t                                   expected_src_addr;
    uint32_t                                   expected_dst_addr;
    uint32_t                                   expected_seq;
    uint32_t                                   expected_ack;
    uint32_t                                   pause_generation;
    uint16_t                                   src_port;
    uint16_t                                   dst_port;
    uint16_t                                   expected_src_port;
    uint16_t                                   expected_dst_port;
    line_t                                    *line;
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets;
    uint32_t                                   queued_packets_count;
    uint32_t                                   queued_packets_capacity;
    bool                                       confirmed;
    bool                                       release_pending;
    bool                                       paused;
} ipmanipulator_smuggle_fin_flow_t;

/*
 * Per-worker record of the one Smuggle-FIN flow that this worker currently owns
 * a pause on. It replaces the old full-table scan and is only mutated on the
 * flow-owner worker; cross-worker reverse traffic resolves the normalized tuple
 * in the shared table instead of touching this registry.
 */
typedef struct ipmanipulator_smuggle_fin_worker_pause_s
{
    ipmanipulator_flow_key_t key;
    uint32_t                 pause_generation;
    bool                     installed;
} ipmanipulator_smuggle_fin_worker_pause_t;

typedef struct ipmanipulator_tstate_s
{
    uint64_t trick_proto_swap : 1;
    uint64_t trick_sni_blender : 1;
    uint64_t trick_first_sni : 1;
    uint64_t trick_smuggle_sni : 1;
    uint64_t trick_overlap_sni : 1;
    uint64_t trick_synfin_sni : 1;
    uint64_t trick_ech_sni : 1;
    uint64_t trick_smuggle_fin : 1;
    uint64_t trick_tcp_bit_changes : 1;
    uint64_t trick_packet_duplicate : 1;
    uint64_t trick_preserve_tcp_bitflags : 1;
    uint64_t trick_source_port_ghost : 1;
    uint64_t trick_dest_port_ghost : 1;

    /* TCP has exactly one reversible replacement number, so every fragment of
     * one datagram is mapped identically and the downstream restore is exact. */
    int trick_proto_swap_tcp_number;
    int trick_proto_swap_udp_number;

    int trick_sni_blender_packets_count;
    int trick_sni_blender_packets_delay_max;
    int trick_packet_duplicate_count;

    bool     trick_first_sni_random_tcp_sequence;
    char    *trick_first_sni_value;
    uint16_t trick_first_sni_value_len;
    uint32_t trick_first_sni_count;
    uint32_t trick_first_sni_replay_delay_ms;
    uint32_t trick_first_sni_final_delay_ms;
    int      trick_first_sni_ttl;

    node_t        internal_tls_client_node;
    struct cJSON *internal_tls_client_settings;
    tunnel_t     *internal_tls_client_tunnel;

    char     *trick_smuggle_sni_value;
    uint16_t  trick_smuggle_sni_value_len;
    uint32_t  trick_smuggle_sni_delay_ms;
    node_t   *trick_real_sni_upstream_node;
    tunnel_t *trick_real_sni_upstream_tunnel;
    tunnel_t *trick_real_sni_tls_client_tunnel;

    char     *trick_overlap_sni_value;
    uint16_t  trick_overlap_sni_value_len;
    uint32_t  trick_overlap_sni_delay_ms;
    uint32_t  trick_overlap_sni_hold_timeout_ms;
    int       trick_overlap_sni_syn_ttl;
    tunnel_t *trick_overlap_sni_tls_client_tunnel;

    char     *trick_synfin_sni_value;
    uint16_t  trick_synfin_sni_value_len;
    uint32_t  trick_synfin_sni_hold_timeout_ms;
    uint16_t  trick_synfin_sni_additional_range_min;
    uint16_t  trick_synfin_sni_additional_range_max;
    int       trick_synfin_sni_syn_ttl;
    int       trick_synfin_sni_fin_ttl;
    int       trick_synfin_sni_fake_ttl;
    bool      trick_synfin_sni_random_syn_checksum;
    bool      trick_synfin_sni_random_fin_checksum;
    bool      trick_synfin_sni_random_syn_sequence;
    bool      trick_synfin_sni_random_fin_sequence;
    bool      trick_synfin_sni_use_rst;
    tunnel_t *trick_synfin_sni_tls_client_tunnel;

    char    *trick_ech_sni_value;
    uint16_t trick_ech_sni_value_len;
    uint32_t trick_ech_sni_shard1_delay_ms;
    uint32_t trick_ech_sni_shard2_delay_ms;

    node_t   *trick_real_fin_upstream_node;
    tunnel_t *trick_real_fin_upstream_tunnel;
    uint32_t  trick_smuggle_fin_delay_ms;
    uint32_t  trick_smuggle_fin_pause_timeout_ms;

    wmutex_t                           tls_capture_mutex;
    ipmanipulator_tls_capture_slot_t  *tls_capture_slots;
    uint32_t                           tls_capture_slots_count;
    ipmanipulator_tls_prestart_slot_t *tls_prestart_slots;
    uint32_t                           tls_prestart_slots_count;

    /* Per-enabled-trick active-flow limit shared by every bounded table below. */
    uint32_t trick_stateful_flow_limit;

    ipmanipulator_flow_table_t first_sni_table;
    ipmanipulator_flow_table_t smuggle_table;
    ipmanipulator_flow_table_t overlap_table;
    ipmanipulator_flow_table_t synfin_table;

    ipmanipulator_flow_table_t echsni_table;
    atomic_ullong              echsni_next_generation;
    atomic_ullong              delay_barrier_next_generation;
    atomic_log_rate_limiter_t  egress_warning_limiter;
    atomic_log_rate_limiter_t  worker_mismatch_guidance_limiter;

    ipmanipulator_flow_table_t                smuggle_fin_table;
    atomic_uint                               smuggle_fin_next_pause_generation;
    ipmanipulator_smuggle_fin_worker_pause_t *smuggle_fin_worker_pauses;
    uint32_t                                  smuggle_fin_worker_pauses_count;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_cwr_action;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_ece_action;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_urg_action;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_ack_action;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_psh_action;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_rst_action;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_syn_action;
    enum tcp_bit_action_dynamic_value         up_tcp_bit_fin_action;

    enum tcp_bit_action_dynamic_value down_tcp_bit_cwr_action;
    enum tcp_bit_action_dynamic_value down_tcp_bit_ece_action;
    enum tcp_bit_action_dynamic_value down_tcp_bit_urg_action;
    enum tcp_bit_action_dynamic_value down_tcp_bit_ack_action;
    enum tcp_bit_action_dynamic_value down_tcp_bit_psh_action;
    enum tcp_bit_action_dynamic_value down_tcp_bit_rst_action;
    enum tcp_bit_action_dynamic_value down_tcp_bit_syn_action;
    enum tcp_bit_action_dynamic_value down_tcp_bit_fin_action;

} ipmanipulator_tstate_t;

typedef struct ipmanipulator_lstate_s
{
    int unused;
} ipmanipulator_lstate_t;

enum
{
    kTunnelStateSize = sizeof(ipmanipulator_tstate_t),
    kLineStateSize   = sizeof(ipmanipulator_lstate_t)
};

WW_EXPORT void         ipmanipulatorDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *ipmanipulatorCreate(node_t *node);
WW_EXPORT api_result_t ipmanipulatorApi(tunnel_t *instance, sbuf_t *message);

void ipmanipulatorOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void ipmanipulatorOnChain(tunnel_t *t, tunnel_chain_t *chain);
void ipmanipulatorOnPrepair(tunnel_t *t);
void ipmanipulatorOnStart(tunnel_t *t);
void ipmanipulatorOnStop(tunnel_t *t);

void ipmanipulatorUpStreamInit(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamEst(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamFinish(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorUpStreamPause(tunnel_t *t, line_t *l);
void ipmanipulatorUpStreamResume(tunnel_t *t, line_t *l);

void ipmanipulatorDownStreamInit(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamEst(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamFinish(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorDownStreamPayloadAfterSmuggleFin(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorDownStreamPause(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamResume(tunnel_t *t, line_t *l);

void ipmanipulatorLinestateInitialize(ipmanipulator_lstate_t *ls);
void ipmanipulatorLinestateDestroy(ipmanipulator_lstate_t *ls);

void ipmanipulatorSendUpstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorSendDownstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorEmitUpstream(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward);
void ipmanipulatorEmitUpstreamPreservingTuple(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward);
bool ipmanipulatorSendWithForwardMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward);
bool ipmanipulatorSendUpstreamMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf);
void ipmanipulatorLogCrossWorkerFlowFailure(tunnel_t *t, const char *trick_name, const char *retained_state_name,
                                            wid_t packet_wid, wid_t owner_wid);
void ipmanipulatorDelayBarrierInitialize(ipmanipulator_tstate_t *state, ipmanipulator_delay_barrier_t *barrier,
                                         uint64_t deadline_ms);
void ipmanipulatorDelayBarrierDestroy(ipmanipulator_delay_barrier_t *barrier);
bool ipmanipulatorDelayBarrierTryEnqueue(tunnel_t *t, ipmanipulator_delay_barrier_kind_e kind,
                                         ipmanipulator_delay_barrier_t *barrier, line_t *l, sbuf_t *buf,
                                         bool remove_after_release, bool *needs_schedule);
bool ipmanipulatorDelayBarrierInstallOrdered(tunnel_t *t, ipmanipulator_delay_barrier_kind_e kind,
                                             ipmanipulator_delay_barrier_t  *barrier,
                                             ipmanipulator_ordered_output_t *outputs, uint32_t count,
                                             bool *needs_schedule);
bool ipmanipulatorDelayBarrierHasPendingOrdered(const ipmanipulator_delay_barrier_t *barrier);
void ipmanipulatorDelayBarrierTake(ipmanipulator_delay_barrier_t *barrier, ipmanipulator_delay_batch_t *batch);
bool ipmanipulatorDelayBarrierSchedule(tunnel_t *t, const ipmanipulator_flow_key_t *key,
                                       ipmanipulator_delay_barrier_kind_e kind, uint64_t generation, wid_t wid,
                                       uint32_t delay_ms);
/*
 * Flushes a barrier whose timer could not be armed. Detaches under the shard
 * lock, then emits everything the barrier still owns in order. Generation-guarded
 * and safe to call more than once: a barrier that was already taken yields
 * nothing. Must run on the worker that owns the retained lines.
 */
void ipmanipulatorDelayBarrierFailOpen(tunnel_t *t, const ipmanipulator_flow_key_t *key,
                                       ipmanipulator_delay_barrier_kind_e kind, uint64_t generation);
bool ipmanipulatorDelayBatchSendUpstream(tunnel_t *t, ipmanipulator_delay_batch_t *batch);
bool ipmanipulatorShouldLogEgressWarning(ipmanipulator_tstate_t *state);

uint64_t ipmanipulatorAllocateFlowGeneration(ipmanipulator_tstate_t *state);
#ifdef IPMANIPULATOR_DELAY_BARRIER_TEST_HOOKS
void ipmanipulatorDelayBarrierTestSetNow(uint64_t now_ms);
void ipmanipulatorDelayBarrierTestSetScheduleFailure(bool should_fail);
void ipmanipulatorDelayBarrierTestFire(tunnel_t *t, const ipmanipulator_flow_key_t *key,
                                       ipmanipulator_delay_barrier_kind_e kind, uint64_t generation);
#endif
uint8_t  ipmanipulatorResolveTransportProtocol(const ipmanipulator_tstate_t *state, uint8_t packet_protocol);
uint32_t portghosttrickGetTailLength(const ipmanipulator_tstate_t *state);
bool     portghosttrickApply(tunnel_t *t, line_t *l, sbuf_t **buf_ptr);
bool     portghosttrickRestore(tunnel_t *t, line_t *l, sbuf_t **buf_ptr);

sbuf_t *clonePacketWithLength(line_t *l, sbuf_t *buf, uint32_t new_len);
bool    parseTlsRecordSni(const uint8_t *tls, uint32_t tls_len, sni_match_t *match);
bool    parseClientHelloSni(const uint8_t *packet, uint32_t packet_length, sni_match_t *match);
/*
 * Reports whether a TCP payload begins a TLS ClientHello and whether the whole
 * record fits in this segment. Tricks that combine two contiguous segments use
 * it to avoid holding a segment that nothing can complete.
 */
ipmanipulator_tls_clienthello_start_status_e ipmanipulatorInspectTlsPayloadClientHelloStart(
    const uint8_t *payload, uint32_t payload_len, uint32_t *tls_record_total_len_out);

void ipmanipulatorForwardCapturedPacketNormal(tunnel_t *t, line_t *l, sbuf_t *buf);

sbuf_t                            *smugglesnitrickGenerateTlsClientHello(tunnel_t *t, line_t *l);
ipmanipulator_tls_capture_status_e ipmanipulatorCaptureTlsClientHello(tunnel_t *t, line_t *l, sbuf_t *buf,
                                                                      ipmanipulator_tls_capture_kind_e  kind,
                                                                      ipmanipulator_tls_capture_slot_t *out_slot);
/*
 * Same as above, but the capture is tagged with an owner flow generation so a
 * timeout, eviction, close or tuple reuse can tell a live capture from one that
 * belongs to a replaced generation. First-SNI and Smuggle-SNI pass zero.
 */
ipmanipulator_tls_capture_status_e ipmanipulatorCaptureTlsClientHelloForOwner(
    tunnel_t *t, line_t *l, sbuf_t *buf, ipmanipulator_tls_capture_kind_e kind, uint64_t owner_generation,
    ipmanipulator_tls_capture_slot_t *out_slot);
/*
 * Detaches a capture slot by kind, normalized tuple and owner generation. The
 * caller owns the returned slot and decides whether to release, recycle or
 * dispose of it -- always after this call returns.
 */
bool ipmanipulatorTakeMatchingCaptureSlot(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                          uint16_t dst_port, ipmanipulator_tls_capture_kind_e kind,
                                          uint64_t owner_generation, bool match_any_generation,
                                          ipmanipulator_tls_capture_slot_t *out_slot);
void ipmanipulatorReleaseCapturedPacketsNormal(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot);
void ipmanipulatorReleasePendingCaptureOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3);
bool ipmanipulatorFlushMatchingCaptureSlot(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                           uint16_t dst_port, ipmanipulator_tls_capture_kind_e kind);
bool ipmanipulatorFlushMatchingPrestartSlot(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                            uint16_t dst_port, ipmanipulator_tls_capture_kind_e kind);
bool ipmanipulatorRecycleMatchingPrestartSlot(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                              uint16_t dst_port, ipmanipulator_tls_capture_kind_e kind);
void ipmanipulatorRecycleCapturedTlsPackets(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot);
void ipmanipulatorDestroyCapturedTlsPackets(ipmanipulator_tls_capture_slot_t *slot);
void ipmanipulatorDestroyTlsCaptureState(tunnel_t *t);
void smugglesnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                       uint16_t dst_port);
/*
 * Fails an ECH flow generation open after a capture timeout, eviction or parse
 * failure. A generation mismatch is a no-op so a stale capture can never touch
 * a replacement generation.
 */
void echsnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                   uint16_t dst_port, uint64_t generation);

ipmanipulator_config_validation_e ipmanipulatorValidateTrickCompatibility(const ipmanipulator_tstate_t *state);
