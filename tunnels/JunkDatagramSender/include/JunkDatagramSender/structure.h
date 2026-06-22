#pragma once

#include "module.h"
#include "wwapi.h"

typedef enum junkdatagramsender_direction_e
{
    kJunkDatagramSenderDirectionUpstream = 0,
    kJunkDatagramSenderDirectionDownstream
} junkdatagramsender_direction_t;

typedef struct junkdatagramsender_tstate_s
{
    uint64_t selected_protocol_mask;
    uint32_t packet_count_min;
    uint32_t packet_count_max;
    uint32_t keep_sending_max_ms;
    uint32_t resend_again_times;
} junkdatagramsender_tstate_t;

typedef struct junkdatagramsender_lstate_s
{
    uint32_t remaining_resend_again_times;
} junkdatagramsender_lstate_t;

enum
{
    kJunkDatagramSenderDefaultPacketCount      = 1,
    kJunkDatagramSenderDefaultResendAgainTimes = 1,
    kJunkDatagramSenderMaxPacketsPerLine       = 256,
    kJunkDatagramSenderMaxResendAgainTimes     = 256,
    kJunkDatagramSenderDefaultMinPacketSize    = 12,
    kJunkDatagramSenderDefaultMaxPacketSize    = 1200,
    kTunnelStateSize                           = sizeof(junkdatagramsender_tstate_t),
    kLineStateSize                             = sizeof(junkdatagramsender_lstate_t)
};

WW_EXPORT void         junkdatagramsenderTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *junkdatagramsenderTunnelCreate(node_t *node);
WW_EXPORT api_result_t junkdatagramsenderTunnelApi(tunnel_t *instance, sbuf_t *message);

void junkdatagramsenderTunnelOnPrepair(tunnel_t *t);
void junkdatagramsenderTunnelOnStart(tunnel_t *t);
void junkdatagramsenderTunnelOnStop(tunnel_t *t);

void junkdatagramsenderTunnelUpStreamInit(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelUpStreamEst(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void junkdatagramsenderTunnelUpStreamPause(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelUpStreamResume(tunnel_t *t, line_t *l);

void junkdatagramsenderTunnelDownStreamInit(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelDownStreamEst(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void junkdatagramsenderTunnelDownStreamPause(tunnel_t *t, line_t *l);
void junkdatagramsenderTunnelDownStreamResume(tunnel_t *t, line_t *l);

bool junkdatagramsenderLoadSettings(junkdatagramsender_tstate_t *ts, const cJSON *settings);

void junkdatagramsenderLinestateInitialize(junkdatagramsender_lstate_t *ls, const junkdatagramsender_tstate_t *ts);
void junkdatagramsenderLinestateDestroy(junkdatagramsender_lstate_t *ls);
bool junkdatagramsenderSendJunk(tunnel_t *t, line_t *l, junkdatagramsender_direction_t direction);
bool junkdatagramsenderIsWorkerPacketLine(tunnel_t *t, line_t *l);
