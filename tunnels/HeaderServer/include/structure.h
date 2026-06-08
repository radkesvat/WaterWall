#pragma once

#include "wwapi.h"

typedef enum headerserver_override_mode_e
{
    kHeaderServerOverrideModeNone = 0,
    kHeaderServerOverrideModeConstant,
    kHeaderServerOverrideModeHeaderPort
} headerserver_override_mode_e;

typedef enum headerserver_phase_e
{
    kHeaderServerPhaseNone = 0,
    kHeaderServerPhaseWaitHeader,
    kHeaderServerPhaseEstablished
} headerserver_phase_e;

typedef struct headerserver_tstate_s
{
    headerserver_override_mode_e override_mode;
    uint16_t                     constant_port;
} headerserver_tstate_t;

typedef struct headerserver_lstate_s
{
    headerserver_phase_e phase;
    buffer_stream_t      read_stream;
} headerserver_lstate_t;

enum
{
    kHeaderServerHeaderSize     = 2,
    kHeaderServerMinAllowedPort = 10,
    kTunnelStateSize            = sizeof(headerserver_tstate_t),
    kLineStateSize              = sizeof(headerserver_lstate_t)
};

WW_EXPORT void         headerserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *headerserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t headerserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void headerserverTunnelOnPrepair(tunnel_t *t);
void headerserverTunnelOnStart(tunnel_t *t);
void headerserverTunnelOnStop(tunnel_t *t);

void headerserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void headerserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void headerserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void headerserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void headerserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void headerserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void headerserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void headerserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void headerserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void headerserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void headerserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void headerserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

bool headerserverLoadSettings(headerserver_tstate_t *ts, const cJSON *settings);
void headerserverLinestateInitialize(headerserver_lstate_t *ls, line_t *l, headerserver_tstate_t *ts);
void headerserverLinestateDestroy(headerserver_lstate_t *ls);
void headerserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void headerserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void headerserverCloseLineFromProtocolError(tunnel_t *t, line_t *l);
