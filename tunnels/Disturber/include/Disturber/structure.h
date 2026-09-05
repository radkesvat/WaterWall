#pragma once

#include "wwapi.h"

typedef struct disturber_tstate_s
{
    bool disturb_upstream;
    bool disturb_downstream;
    int  chance_instant_close;
    int  chance_middle_close;
    int  chance_payload_corruption;
    int  chance_payload_loss;
    int  chance_payload_duplication;
    int  chance_payload_out_of_order;
    int  chance_payload_delay;
    int  chance_connection_deadhang;
    int  delay_min_ms;
    int  delay_max_ms;

} disturber_tstate_t;

typedef struct disturber_direction_lstate_s
{
    bool is_deadhang; // the connection is dead, no packet type will be transmitted, but only close
    bool finished;    // payload publication in this direction is terminal after packet Finish

    sbuf_t *held_payload; // store  a payload and wait for next, to be able to send them out of order

    noncrypto_percent_gate_t instant_close_gate;
    noncrypto_percent_gate_t middle_close_gate;
    noncrypto_percent_gate_t payload_corruption_gate;
    noncrypto_percent_gate_t payload_loss_gate;
    noncrypto_percent_gate_t payload_duplication_gate;
    noncrypto_percent_gate_t payload_out_of_order_gate;
    noncrypto_percent_gate_t payload_delay_gate;
    noncrypto_percent_gate_t connection_deadhang_gate;
} disturber_direction_lstate_t;

typedef struct disturber_lstate_s
{
    disturber_direction_lstate_t upstream;
    disturber_direction_lstate_t downstream;
} disturber_lstate_t;

typedef enum disturber_payload_direction_e
{
    kDisturberPayloadDirectionUpstream   = 0,
    kDisturberPayloadDirectionDownstream = 1
} disturber_payload_direction_e;

enum
{
    kTunnelStateSize = sizeof(disturber_tstate_t),
    kLineStateSize   = sizeof(disturber_lstate_t)
};

WW_EXPORT void         disturberTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *disturberTunnelCreate(node_t *node);
WW_EXPORT api_result_t disturberTunnelApi(tunnel_t *instance, sbuf_t *message);

void disturberTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void disturberTunnelUpStreamInit(tunnel_t *t, line_t *l);
void disturberTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void disturberTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void disturberTunnelDownStreamInit(tunnel_t *t, line_t *l);
void disturberTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void disturberTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void disturberLinestateInitialize(disturber_lstate_t *ls, const disturber_tstate_t *ts);
void disturberLinestateDestroy(line_t *l, disturber_lstate_t *ls);
void disturberTunnelPayload(tunnel_t *t, line_t *l, sbuf_t *buf, disturber_payload_direction_e direction);
bool disturberIsWorkerPacketLine(tunnel_t *t, line_t *l);
void disturberPacketLineFinish(tunnel_t *t, line_t *l, disturber_payload_direction_e direction);
