#pragma once

#include "ReverseClient/reverseclient_activation.h"
#include "ReverseClient/reverseclient_handshake.h"
#include "wwapi.h"

typedef struct reverseserver_lstate_s
{
    struct reverseserver_lstate_s *prev; // previous tunnel state in the linked list
    struct reverseserver_lstate_s *next; // next tunnel state in the linked list
    line_t                        *u;
    line_t                        *d;
    buffer_queue_t                 pending;
    buffer_budget_t                pending_budget;
    uint64_t                       replay_admitted;
    uint32_t                       replay_admitted_buffers;
    uint32_t                       handshake_read;
    bool                           paired;
    bool                           handshaked;
    bool                           replaying;
    bool                           output_paused;
    bool                           source_paused;
} reverseserver_lstate_t;

typedef struct reverseserver_thread_box_s
{
    reverseserver_lstate_t *u_root;
    reverseserver_lstate_t *d_root;
    atomic_uint             u_count;
    atomic_uint             d_count;
} reverseserver_thread_box_t;

typedef struct reverseserver_tstate_s
{
    uint8_t                   *handshake_bytes;
    uint32_t                   handshake_length;
    uint32_t                   activation_min_size;
    uint32_t                   activation_max_size;
    reverseserver_thread_box_t threadlocal_pool[];
} reverseserver_tstate_t;

enum
{
    kTunnelStateSize = sizeof(reverseserver_tstate_t),
    kLineStateSize   = sizeof(reverseserver_lstate_t),
    kReverseServerPendingBytes   = 2 * 1024 * 1024,
    kReverseServerPendingBuffers = 1024
};

WW_EXPORT void         reverseserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *reverseserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t reverseserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void reverseserverTunnelUpStreamInit(tunnel_t *t, line_t *d);
void reverseserverTunnelUpStreamFinish(tunnel_t *t, line_t *d);
void reverseserverTunnelUpStreamPayload(tunnel_t *t, line_t *d, sbuf_t *buf);
void reverseserverTunnelUpStreamPause(tunnel_t *t, line_t *d);
void reverseserverTunnelUpStreamResume(tunnel_t *t, line_t *d);

void reverseserverTunnelDownStreamInit(tunnel_t *t, line_t *u);
void reverseserverTunnelDownStreamEst(tunnel_t *t, line_t *u);
void reverseserverTunnelDownStreamFinish(tunnel_t *t, line_t *u);
void reverseserverTunnelDownStreamPayload(tunnel_t *t, line_t *u, sbuf_t *buf);
void reverseserverTunnelDownStreamPause(tunnel_t *t, line_t *u);
void reverseserverTunnelDownStreamResume(tunnel_t *t, line_t *u);

void reverseserverLinestateInitialize(reverseserver_lstate_t *ls, line_t *u, line_t *d);
void reverseserverLinestateDestroy(reverseserver_lstate_t *ls);

void reverseserverAddConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);
void reverseserverRemoveConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);
void reverseserverAddConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);
void reverseserverRemoveConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);

void reverseserverPair(tunnel_t *t, line_t *u, line_t *d);
void reverseserverDrainPair(tunnel_t *t, line_t *u);
bool reverseserverQueuePairedPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
bool reverseserverRetainPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
bool reverseserverReconcileSource(tunnel_t *t, line_t *line);
void reverseserverCloseLine(tunnel_t *t, line_t *line);
void reverseserverNotifyWaitingPeers(tunnel_t *t, wid_t user_wid);
