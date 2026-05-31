#pragma once

#include "wwapi.h"

enum
{
    kBgp4ClientMarkerByte          = 0xFF,
    kBgp4ClientMarkerLength        = 16,
    kBgp4ClientLengthSize          = 2,
    kBgp4ClientTypeSize            = 1,
    kBgp4ClientFrameHeaderSize     = kBgp4ClientMarkerLength + kBgp4ClientLengthSize,
    kBgp4ClientFramePrefixSize     = kBgp4ClientFrameHeaderSize + kBgp4ClientTypeSize,
    kBgp4ClientTypeOpen            = 1,
    kBgp4ClientTypeUpdate          = 2,
    kBgp4ClientTypeNotification    = 3,
    kBgp4ClientTypeKeepAlive       = 4,
    kBgp4ClientTypeRouteRefresh    = 5,
    kBgp4ClientOpenHeaderSize      = 10,
    kBgp4ClientOpenOptionalMin     = 3,
    kBgp4ClientOpenOptionalRange   = 8,
    kBgp4ClientOpenOptionalMax     = kBgp4ClientOpenOptionalMin + kBgp4ClientOpenOptionalRange - 1,
    kBgp4ClientRequiredPaddingLeft = kBgp4ClientFramePrefixSize + kBgp4ClientOpenHeaderSize +
                                     kBgp4ClientOpenOptionalMax,
    kBgp4ClientMaxBodyLength       = UINT16_MAX,
    kBgp4ClientMaxBufferedBytes    = (kBgp4ClientFrameHeaderSize + kBgp4ClientMaxBodyLength) * 2,
};

typedef enum bgp4client_phase_e
{
    kBgp4ClientPhaseNone = 0,
    kBgp4ClientPhaseActive
} bgp4client_phase_e;

typedef struct bgp4client_tstate_s
{
    uint16_t as_number;
    uint32_t router_id;
    hash_t   password_hash;
} bgp4client_tstate_t;

typedef struct bgp4client_lstate_s
{
    bgp4client_phase_e phase;
    buffer_stream_t    read_stream;
    bool               open_sent;
} bgp4client_lstate_t;

enum
{
    kTunnelStateSize = sizeof(bgp4client_tstate_t),
    kLineStateSize   = sizeof(bgp4client_lstate_t)
};

WW_EXPORT void         bgp4clientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *bgp4clientTunnelCreate(node_t *node);
WW_EXPORT api_result_t bgp4clientTunnelApi(tunnel_t *instance, sbuf_t *message);

void bgp4clientTunnelOnPrepair(tunnel_t *t);
void bgp4clientTunnelOnStart(tunnel_t *t);

void bgp4clientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void bgp4clientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void bgp4clientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void bgp4clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void bgp4clientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void bgp4clientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void bgp4clientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void bgp4clientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void bgp4clientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void bgp4clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void bgp4clientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void bgp4clientTunnelDownStreamResume(tunnel_t *t, line_t *l);

bool bgp4clientLoadSettings(bgp4client_tstate_t *ts, const cJSON *settings);
void bgp4clientLinestateInitialize(bgp4client_lstate_t *ls, line_t *l);
void bgp4clientLinestateDestroy(bgp4client_lstate_t *ls);
void bgp4clientCloseLine(tunnel_t *t, line_t *l);
bool bgp4clientWrapPayload(tunnel_t *t, line_t *l, sbuf_t **buf_io, uint8_t type);
bool bgp4clientWrapFirstOpenPayload(tunnel_t *t, line_t *l, sbuf_t **buf_io);
bool bgp4clientReadFrame(tunnel_t *t, line_t *l, buffer_stream_t *stream, sbuf_t **payload_out);
uint8_t bgp4clientNextPayloadType(void);
