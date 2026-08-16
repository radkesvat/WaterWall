#pragma once

#include "ReverseClient/reverseclient_handshake.h"
#include "wwapi.h"

typedef struct reverseclient_pair_s reverseclient_pair_t;

typedef struct reverseclient_thread_box_s
{
    reverseclient_pair_t *owned_pairs;
    uint32_t              unused_cons_count;
    uint32_t              connecting_cons_count;

} reverseclient_thread_box_t;

typedef struct reverseclient_tstate_s
{
    idle_table_t *starved_connections;
    atomic_uint   reverse_cons;
    atomic_uint   round_index;
    atomic_bool   stopping;
    uint8_t      *handshake_bytes;
    uint32_t      handshake_length;
    uint32_t      min_unused_cons;

    MSVC_ATTR_ALIGNED_16 reverseclient_thread_box_t threadlocal_pool[] GNU_ATTR_ALIGNED_16;
} reverseclient_tstate_t;

typedef enum reverseclient_pair_phase_e
{
    kReverseClientPairConnecting = 0,
    kReverseClientPairUnused,
    kReverseClientPairActive
} reverseclient_pair_phase_e;

struct reverseclient_pair_s
{
    reverseclient_pair_t      *next;
    reverseclient_pair_t      *prev;
    idle_item_t               *idle_handle;
    tunnel_t                  *t;
    line_t                    *u;
    line_t                    *d;
    reverseclient_pair_phase_e phase;
    bool                       registered : 1;
    bool                       upstream_init_sent : 1;
    bool                       downstream_init_sent : 1;
    bool                       closing : 1;
};

typedef struct reverseclient_lstate_s
{
    reverseclient_pair_t *pair;
} reverseclient_lstate_t;

typedef enum reverseclient_close_origin_e
{
    kReverseClientCloseInternal = 0,
    kReverseClientCloseFromNext,
    kReverseClientCloseFromPrev,
    kReverseClientCloseIdleExpiry
} reverseclient_close_origin_e;

enum
{
    kTunnelStateSize                = sizeof(reverseclient_tstate_t),
    kLineStateSize                  = sizeof(reverseclient_lstate_t),
    kPreconnectDelayShort           = 10,
    kPreconnectDelayLong            = 750,
    kConnectionStarvationTimeOutSec = 30
};

WW_EXPORT void         reverseclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *reverseclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t reverseclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void reverseclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void reverseclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void reverseclientTunnelOnPrepair(tunnel_t *t);
void reverseclientTunnelOnStart(tunnel_t *t);
void reverseclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void reverseclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void reverseclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);

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

void reverseclientLinestateInitialize(reverseclient_lstate_t *ls, reverseclient_pair_t *pair);
void reverseclientLinestateDestroy(reverseclient_lstate_t *ls);

void   reverseclientInitiateConnectOnWorker(tunnel_t *t, wid_t wid, bool delay);
void   reverseclientOnStarvedConnectionExpire(idle_item_t *idle_con);
void   reverseclientClosePair(reverseclient_pair_t *pair, reverseclient_close_origin_e origin);
size_t reverseclientOwnedPairCount(tunnel_t *t, wid_t wid);
