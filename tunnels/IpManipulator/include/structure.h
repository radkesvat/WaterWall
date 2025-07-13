#pragma once

#include "wwapi.h"

enum tcp_bit_action_dynamic_value
{
    kDvsNoAction = kDvsEmpty,
    kDvsOff      = kDvsFirstOption,
    kDvsOn,
    kDvsSwapCwr,
    kDvsSwapEce,
    kDvsSwapUrg,
    kDvsSwapAck,
    kDvsSwapPsh,
    kDvsSwapRst,
    kDvsSwapSyn,
    kDvsSwapFin
};

typedef struct ipmanipulator_tstate_s
{
    uint64_t trick_proto_swap : 1;
    uint64_t trick_sni_blender : 1;
    uint64_t trick_tcp_bit_changes : 1;

    int trick_proto_swap_tcp_number;
    int trick_proto_swap_udp_number;

    int trick_sni_blender_packets_count;
    int trick_sni_blender_packets_delay_max;

    enum tcp_bit_action_dynamic_value up_tcp_bit_cwr_action;
    enum tcp_bit_action_dynamic_value up_tcp_bit_ece_action;
    enum tcp_bit_action_dynamic_value up_tcp_bit_urg_action;
    enum tcp_bit_action_dynamic_value up_tcp_bit_ack_action;
    enum tcp_bit_action_dynamic_value up_tcp_bit_psh_action;
    enum tcp_bit_action_dynamic_value up_tcp_bit_rst_action;
    enum tcp_bit_action_dynamic_value up_tcp_bit_syn_action;
    enum tcp_bit_action_dynamic_value up_tcp_bit_fin_action;

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
    kLineStateSize   = sizeof(ipmanipulator_lstate_t),

    kSniBlenderTrickMaxPacketsCount = 16
};

WW_EXPORT void         ipmanipulatorDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *ipmanipulatorCreate(node_t *node);
WW_EXPORT api_result_t ipmanipulatorApi(tunnel_t *instance, sbuf_t *message);

void ipmanipulatorOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void ipmanipulatorOnChain(tunnel_t *t, tunnel_chain_t *chain);
void ipmanipulatorOnPrepair(tunnel_t *t);
void ipmanipulatorOnStart(tunnel_t *t);

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
