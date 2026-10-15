#pragma once

#include "../../../Internals/Bgp4Common/stream.h"
#include "wwapi.h"

typedef struct bgp4server_tstate_s
{
    uint16_t as_number;
    uint32_t router_id;
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

void    bgp4serverLinestateInitialize(bgp4server_lstate_t *ls, line_t *l);
void    bgp4serverLinestateDestroy(bgp4server_lstate_t *ls);
