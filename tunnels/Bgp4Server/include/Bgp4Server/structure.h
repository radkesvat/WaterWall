#pragma once

#include "wwapi.h"

enum
{
    kBgp4ServerMarkerByte       = 0xFF,
    kBgp4ServerMarkerLength     = 16,
    kBgp4ServerLengthSize       = 2,
    kBgp4ServerTypeSize         = 1,
    kBgp4ServerFrameHeaderSize  = kBgp4ServerMarkerLength + kBgp4ServerLengthSize,
    kBgp4ServerFramePrefixSize  = kBgp4ServerFrameHeaderSize + kBgp4ServerTypeSize,
    kBgp4ServerTypeOpen         = 1,
    kBgp4ServerTypeUpdate       = 2,
    kBgp4ServerTypeNotification = 3,
    kBgp4ServerTypeKeepAlive    = 4,
    kBgp4ServerTypeRouteRefresh = 5,
    kBgp4ServerOpenHeaderSize   = 10,
    kBgp4ServerMaxBodyLength    = UINT16_MAX,
    kBgp4ServerMaxBufferedBytes = (kBgp4ServerFrameHeaderSize + kBgp4ServerMaxBodyLength) * 2,
};

typedef struct bgp4server_tstate_s
{
    uint16_t as_number;
    uint32_t router_id;
    hash_t   password_hash;
} bgp4server_tstate_t;

typedef struct bgp4server_lstate_s
{
    buffer_stream_t read_stream;
    bool            open_received;
} bgp4server_lstate_t;

enum
{
    kTunnelStateSize = sizeof(bgp4server_tstate_t),
    kLineStateSize   = sizeof(bgp4server_lstate_t)
};

WW_EXPORT void         bgp4serverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *bgp4serverTunnelCreate(node_t *node);
WW_EXPORT api_result_t bgp4serverTunnelApi(tunnel_t *instance, sbuf_t *message);

void bgp4serverTunnelOnPrepair(tunnel_t *t);
void bgp4serverTunnelOnStart(tunnel_t *t);
void bgp4serverTunnelOnStop(tunnel_t *t);

void bgp4serverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void bgp4serverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void bgp4serverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void bgp4serverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void bgp4serverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void bgp4serverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void bgp4serverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void bgp4serverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void bgp4serverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void bgp4serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void bgp4serverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void bgp4serverTunnelDownStreamResume(tunnel_t *t, line_t *l);

bool    bgp4serverLoadSettings(bgp4server_tstate_t *ts, const cJSON *settings);
void    bgp4serverLinestateInitialize(bgp4server_lstate_t *ls, line_t *l);
void    bgp4serverLinestateDestroy(bgp4server_lstate_t *ls);
void    bgp4serverCloseLine(tunnel_t *t, line_t *l);
bool    bgp4serverWrapPayload(tunnel_t *t, line_t *l, sbuf_t **buf_io, uint8_t type);
bool    bgp4serverReadFrame(tunnel_t *t, line_t *l, buffer_stream_t *stream, sbuf_t **body_out);
bool    bgp4serverStripUpstreamBody(tunnel_t *t, line_t *l, bgp4server_lstate_t *ls, sbuf_t *body);
uint8_t bgp4serverNextPayloadType(void);
