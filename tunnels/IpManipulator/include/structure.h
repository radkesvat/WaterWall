#pragma once

#include "wwapi.h"

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
    kIpManipulatorTlsCaptureKindSmuggleSni
} ipmanipulator_tls_capture_kind_e;

typedef enum ipmanipulator_tls_capture_status_e
{
    kIpManipulatorTlsCaptureStatusMiss = 0,
    kIpManipulatorTlsCaptureStatusPending,
    kIpManipulatorTlsCaptureStatusReady,
    kIpManipulatorTlsCaptureStatusBypassed
} ipmanipulator_tls_capture_status_e;

enum
{
    kSniBlenderTrickMaxPacketsCount        = 16,
    kIpManipulatorTlsCaptureSlotsPerWorker = 16,
    kIpManipulatorTlsCaptureMaxPackets     = 16
};

typedef struct ipmanipulator_captured_packet_s
{
    line_t *line;
    sbuf_t *buf;
} ipmanipulator_captured_packet_t;

typedef struct ipmanipulator_tls_capture_slot_s
{
    sbuf_t                          *assembled_packet;
    uint64_t                         last_update_ms;
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
    uint64_t                         last_update_ms;
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

enum
{
    kIpManipulatorSmuggleSavedPacketsCount = 1,
    kIpManipulatorSmuggleInitialFlows      = 32
};

typedef struct ipmanipulator_smuggle_saved_packet_s
{
    line_t  *line;
    sbuf_t  *packet;
    uint16_t payload_len;
} ipmanipulator_smuggle_saved_packet_t;

typedef struct ipmanipulator_smuggle_flow_s
{
    uint64_t                             created_ms;
    uint64_t                             last_activity_ms;
    uint64_t                             delay_window_until_ms;
    uint32_t                             src_addr;
    uint32_t                             dst_addr;
    uint16_t                             src_port;
    uint16_t                             dst_port;
    uint8_t                              warmup_packets_seen;
    uint8_t                              capture_packets_seen;
    ipmanipulator_smuggle_flow_phase_e   phase;
    bool                                 active;
    uint32_t                             captured_payload_sum;
    ipmanipulator_smuggle_saved_packet_t saved_packets[kIpManipulatorSmuggleSavedPacketsCount];
} ipmanipulator_smuggle_flow_t;

typedef struct ipmanipulator_firstsni_flow_s
{
    uint64_t created_ms;
    uint64_t last_activity_ms;
    uint64_t delay_window_until_ms;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    bool     active;
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
    uint32_t                           src_addr;
    uint32_t                           dst_addr;
    uint32_t                           expected_downstream_seq;
    uint16_t                           src_port;
    uint16_t                           dst_port;
    uint16_t                           expected_downstream_ip_total_len;
    uint16_t                           expected_downstream_fingerprint;
    uint8_t                            warmup_packets_seen;
    ipmanipulator_overlap_flow_phase_e phase;
    bool                               active;
    bool                               ignore_expected_downstream_packet;
    ipmanipulator_captured_packet_t    held_packet;
    sbuf_t                            *synack_packet;
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
    uint32_t                          src_addr;
    uint32_t                          dst_addr;
    uint16_t                          src_port;
    uint16_t                          dst_port;
    uint8_t                           warmup_packets_seen;
    ipmanipulator_synfin_flow_phase_e phase;
    bool                              active;
    ipmanipulator_captured_packet_t   held_packet;
    sbuf_t                           *syn_packet_template;
} ipmanipulator_synfin_flow_t;

typedef enum ipmanipulator_echsni_flow_phase_e
{
    kIpManipulatorEchSniFlowPhaseWarmup = 0,
    kIpManipulatorEchSniFlowPhaseHoldThird,
    kIpManipulatorEchSniFlowPhasePassthrough,
    kIpManipulatorEchSniFlowPhaseBlocked
} ipmanipulator_echsni_flow_phase_e;

typedef struct ipmanipulator_echsni_flow_s
{
    uint64_t                          created_ms;
    uint64_t                          last_activity_ms;
    uint64_t                          shard1_release_at_ms;
    uint64_t                          shard2_release_at_ms;
    uint32_t                          src_addr;
    uint32_t                          dst_addr;
    uint16_t                          src_port;
    uint16_t                          dst_port;
    uint8_t                           warmup_packets_seen;
    ipmanipulator_echsni_flow_phase_e phase;
    bool                              active;
    ipmanipulator_captured_packet_t   held_packet;
} ipmanipulator_echsni_flow_t;

typedef struct ipmanipulator_smuggle_fin_flow_s
{
    uint64_t last_activity_ms;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    bool     active;
    bool     confirmed;
} ipmanipulator_smuggle_fin_flow_t;

typedef enum ipmanipulator_smuggle_fin_queue_direction_e
{
    kIpManipulatorSmuggleFinQueueDirectionUpstream = 0,
    kIpManipulatorSmuggleFinQueueDirectionDownstream
} ipmanipulator_smuggle_fin_queue_direction_e;

typedef struct ipmanipulator_smuggle_fin_queued_packet_s
{
    sbuf_t                                     *buf;
    ipmanipulator_smuggle_fin_queue_direction_e direction;
} ipmanipulator_smuggle_fin_queued_packet_t;

typedef struct ipmanipulator_smuggle_fin_worker_state_s
{
    uint32_t                                   flow_src_addr;
    uint32_t                                   flow_dst_addr;
    uint32_t                                   expected_src_addr;
    uint32_t                                   expected_dst_addr;
    uint32_t                                   expected_seq;
    uint32_t                                   expected_ack;
    uint16_t                                   flow_src_port;
    uint16_t                                   flow_dst_port;
    uint16_t                                   expected_src_port;
    uint16_t                                   expected_dst_port;
    ipmanipulator_smuggle_fin_queued_packet_t *queued_packets;
    uint32_t                                   queued_packets_count;
    uint32_t                                   queued_packets_capacity;
    bool                                       release_pending;
    bool                                       paused;
} ipmanipulator_smuggle_fin_worker_state_t;

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
    uint64_t trick_bit_transport : 1;
    uint64_t trick_source_port_ghost : 1;
    uint64_t trick_dest_port_ghost : 1;

    int trick_proto_swap_tcp_number;
    int trick_proto_swap_tcp_number_2;
    int trick_proto_swap_tcp_toggle_up;
    int trick_proto_swap_tcp_toggle_down;

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

    char     *trick_smuggle_sni_value;
    uint16_t  trick_smuggle_sni_value_len;
    uint32_t  trick_smuggle_sni_delay_ms;
    node_t   *trick_real_sni_upstream_node;
    tunnel_t *trick_real_sni_upstream_tunnel;
    node_t   *trick_real_sni_tls_client_node;
    tunnel_t *trick_real_sni_tls_client_tunnel;

    char     *trick_overlap_sni_value;
    uint16_t  trick_overlap_sni_value_len;
    uint32_t  trick_overlap_sni_delay_ms;
    int       trick_overlap_sni_syn_ttl;
    node_t   *trick_overlap_sni_server_hello_upstream_node;
    tunnel_t *trick_overlap_sni_server_hello_upstream_tunnel;
    node_t   *trick_overlap_sni_tls_client_node;
    tunnel_t *trick_overlap_sni_tls_client_tunnel;

    char     *trick_synfin_sni_value;
    uint16_t  trick_synfin_sni_value_len;
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
    node_t   *trick_synfin_sni_tls_client_node;
    tunnel_t *trick_synfin_sni_tls_client_tunnel;

    char    *trick_ech_sni_value;
    uint16_t trick_ech_sni_value_len;
    uint32_t trick_ech_sni_shard1_delay_ms;
    uint32_t trick_ech_sni_shard2_delay_ms;

    node_t   *trick_real_fin_upstream_node;
    tunnel_t *trick_real_fin_upstream_tunnel;
    uint32_t  trick_smuggle_fin_delay_ms;

    wmutex_t                           tls_capture_mutex;
    ipmanipulator_tls_capture_slot_t  *tls_capture_slots;
    uint32_t                           tls_capture_slots_count;
    ipmanipulator_tls_prestart_slot_t *tls_prestart_slots;
    uint32_t                           tls_prestart_slots_count;
    wmutex_t                           first_sni_flows_mutex;
    ipmanipulator_firstsni_flow_t     *first_sni_flows;
    uint32_t                           first_sni_flows_capacity;
    wmutex_t                           smuggle_flows_mutex;
    ipmanipulator_smuggle_flow_t      *smuggle_flows;
    uint32_t                           smuggle_flows_capacity;

    wmutex_t                      overlap_flows_mutex;
    ipmanipulator_overlap_flow_t *overlap_flows;
    uint32_t                      overlap_flows_capacity;

    wmutex_t                     synfin_flows_mutex;
    ipmanipulator_synfin_flow_t *synfin_flows;
    uint32_t                     synfin_flows_capacity;

    wmutex_t                     echsni_flows_mutex;
    ipmanipulator_echsni_flow_t *echsni_flows;
    uint32_t                     echsni_flows_capacity;

    wmutex_t                                  smuggle_fin_mutex;
    ipmanipulator_smuggle_fin_flow_t         *smuggle_fin_flows;
    uint32_t                                  smuggle_fin_flows_capacity;
    ipmanipulator_smuggle_fin_worker_state_t *smuggle_fin_worker_states;
    uint32_t                                  smuggle_fin_worker_states_count;
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

void ipmanipulatorOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
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
void ipmanipulatorDownStreamPause(tunnel_t *t, line_t *l);
void ipmanipulatorDownStreamResume(tunnel_t *t, line_t *l);

void ipmanipulatorLinestateInitialize(ipmanipulator_lstate_t *ls);
void ipmanipulatorLinestateDestroy(ipmanipulator_lstate_t *ls);

void     ipmanipulatorSendUpstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf);
void     ipmanipulatorSendDownstreamFinal(tunnel_t *t, line_t *l, sbuf_t *buf);
bool     ipmanipulatorSendWithForwardMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward);
bool     ipmanipulatorSendUpstreamMaybeSegmented(tunnel_t *t, line_t *l, sbuf_t *buf);
uint32_t portghosttrickGetTailLength(const ipmanipulator_tstate_t *state);
bool     portghosttrickApply(tunnel_t *t, line_t *l, sbuf_t **buf_ptr);
bool     portghosttrickRestore(tunnel_t *t, line_t *l, sbuf_t **buf_ptr);

sbuf_t *clonePacketWithLength(line_t *l, sbuf_t *buf, uint32_t new_len);
bool    parseClientHelloSni(const uint8_t *packet, uint32_t packet_length, sni_match_t *match);
ipmanipulator_tls_capture_status_e ipmanipulatorCaptureTlsClientHello(tunnel_t *t, line_t *l, sbuf_t *buf,
                                                                      ipmanipulator_tls_capture_kind_e  kind,
                                                                      ipmanipulator_tls_capture_slot_t *out_slot);
void ipmanipulatorReleaseCapturedPacketsNormal(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot);
void ipmanipulatorRecycleCapturedTlsPackets(tunnel_t *t, ipmanipulator_tls_capture_slot_t *slot);
void ipmanipulatorDestroyCapturedTlsPackets(ipmanipulator_tls_capture_slot_t *slot);
void ipmanipulatorDestroyTlsCaptureState(tunnel_t *t);
