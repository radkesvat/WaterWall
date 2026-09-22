#pragma once

#include "../../../Internals/Bgp4Common/stream.h"
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
};

typedef struct bgp4server_tstate_s
{
    uint16_t as_number;
    uint32_t router_id;
    hash_t   password_hash;
} bgp4server_tstate_t;

typedef bgp_stream_t bgp4server_lstate_t;

enum
{
    kTunnelStateSize = sizeof(bgp4server_tstate_t),
    kLineStateSize   = sizeof(bgp4server_lstate_t)
};

WW_EXPORT tunnel_t    *bgp4serverTunnelCreate(node_t *node);
WW_EXPORT api_result_t bgp4serverTunnelApi(tunnel_t *instance, sbuf_t *message);

void bgp4serverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void bgp4serverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void bgp4serverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void bgp4serverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void bgp4serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

bool    bgp4serverLoadSettings(bgp4server_tstate_t *ts, const cJSON *settings);
bool    bgp4serverLinestateInitialize(bgp4server_lstate_t *ls, line_t *l);
void    bgp4serverLinestateDestroy(bgp4server_lstate_t *ls);
void    bgp4serverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void    bgp4serverTunnelUpStreamResume(tunnel_t *t, line_t *l);
void    bgp4serverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void    bgp4serverTunnelDownStreamResume(tunnel_t *t, line_t *l);
