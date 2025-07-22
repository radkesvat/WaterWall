#pragma once

#include "wwapi.h"

typedef struct reverseserver_lstate_s
{
    struct reverseserver_lstate_s *prev; // previous tunnel state in the linked list
    struct reverseserver_lstate_s *next; // next tunnel state in the linked list
    line_t                        *u;
    line_t                        *d;
    sbuf_t                        *buffering;
    bool                           paired;
    bool                           handshaked;
} reverseserver_lstate_t;

typedef struct reverseserver_thread_box_s
{
    reverseserver_lstate_t *u_root;
    reverseserver_lstate_t *d_root;
    uint32_t                u_count;
    uint32_t                d_count;
} reverseserver_thread_box_t;

typedef struct reverseserver_tstate_s
{
    void                      *unused;
    reverseserver_thread_box_t threadlocal_pool[];
} reverseserver_tstate_t;

enum
{
    kTunnelStateSize = sizeof(reverseserver_tstate_t),
    kLineStateSize   = sizeof(reverseserver_lstate_t),
    kHandShakeByte   = 0xFF, // shared with ReverseClient
    kHandShakeLength = 640,  // shared with ReverseClient
    kMaxBuffering = 65535 // 64kB maximum buffering size for a single connection that handshaked and awiting for a peer
};

WW_EXPORT void         reverseserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *reverseserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t reverseserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void reverseserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void reverseserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void reverseserverTunnelOnPrepair(tunnel_t *t);
void reverseserverTunnelOnStart(tunnel_t *t);

void reverseserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void reverseserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void reverseserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void reverseserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void reverseserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void reverseserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void reverseserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void reverseserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void reverseserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void reverseserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void reverseserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void reverseserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void reverseserverLinestateInitialize(reverseserver_lstate_t *ls, line_t *u, line_t *d);
void reverseserverLinestateDestroy(reverseserver_lstate_t *ls);

void reverseserverAddConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);
void reverseserverRemoveConnectionU(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);
void reverseserverAddConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);
void reverseserverRemoveConnectionD(reverseserver_thread_box_t *box, reverseserver_lstate_t *con);
