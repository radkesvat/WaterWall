#pragma once

#include "../../../Internals/Bgp4Common/stream.h"
#include "wwapi.h"

enum
{
    kBgp4ClientOpenHeaderSize    = 10,
    kBgp4ClientOpenOptionalMin   = 3,
    kBgp4ClientOpenOptionalRange = 8,
    kBgp4ClientOpenOptionalMax   = kBgp4ClientOpenOptionalMin + kBgp4ClientOpenOptionalRange - 1,
    kBgp4ClientRequiredPaddingLeft = kBgpFramePrefix + kBgp4ClientOpenHeaderSize + kBgp4ClientOpenOptionalMax,
};

typedef struct bgp4client_tstate_s
{
    uint16_t as_number;
    uint32_t router_id;
} bgp4client_tstate_t;

typedef bgp_stream_t bgp4client_lstate_t;

enum
{
    kTunnelStateSize = sizeof(bgp4client_tstate_t),
    kLineStateSize   = sizeof(bgp4client_lstate_t)
};

WW_EXPORT tunnel_t    *bgp4clientTunnelCreate(node_t *node);
WW_EXPORT api_result_t bgp4clientTunnelApi(tunnel_t *instance, sbuf_t *message);

void bgp4clientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void bgp4clientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void bgp4clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void bgp4clientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void bgp4clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void    bgp4clientLinestateInitialize(bgp4client_lstate_t *ls, line_t *l);
void    bgp4clientLinestateDestroy(bgp4client_lstate_t *ls);
