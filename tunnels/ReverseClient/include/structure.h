#pragma once

#include "wwapi.h"

typedef struct reverseclient_thread_box_s
{
    uint32_t unused_cons_count;
    uint32_t connecting_cons_count;

} reverseclient_thread_box_t;

typedef struct reverseclient_tstate_s
{
    widle_table_t *starved_connections;
    atomic_uint    reverse_cons;
    atomic_uint    round_index;
    uint32_t       min_unused_cons;

    MSVC_ATTR_ALIGNED_16 reverseclient_thread_box_t threadlocal_pool[] GNU_ATTR_ALIGNED_16;
} reverseclient_tstate_t;

typedef struct reverseclient_lstate_s
{

    widle_item_t *idle_handle;
    tunnel_t     *t;
    line_t       *u;
    line_t       *d;
    bool          pair_connected : 1;
} reverseclient_lstate_t;

enum
{
    kTunnelStateSize                = sizeof(reverseclient_tstate_t),
    kLineStateSize                  = sizeof(reverseclient_lstate_t),
    kHandShakeByte                  = 0xFF, // shared with ReverseServer
    kHandShakeLength                = 640,  // shared with ReverseServer
    kPreconnectDelayShort           = 10,
    kPreconnectDelayLong            = 750,
    kConnectionStarvationTimeOutSec = 600
};

WW_EXPORT void         reverseclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *reverseclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t reverseclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void reverseclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void reverseclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void reverseclientTunnelOnPrepair(tunnel_t *t);
void reverseclientTunnelOnStart(tunnel_t *t);

void reverseclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void reverseclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void reverseclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void reverseclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void reverseclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void reverseclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void reverseclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void reverseclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void reverseclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void reverseclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void reverseclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void reverseclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void reverseclientLinestateInitialize(reverseclient_lstate_t *ls, tunnel_t *t, line_t *u, line_t *d);
void reverseclientLinestateDestroy(reverseclient_lstate_t *ls);

void reverseclientInitiateConnectOnWorker(tunnel_t *t, wid_t wid, bool delay);
void reverseclientOnStarvedConnectionExpire(widle_item_t *idle_con);
