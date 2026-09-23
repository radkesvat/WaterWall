#pragma once

#include "wwapi.h"

typedef enum connectionfisherserver_phase_e
{
    kConnectionFisherServerPhaseClosing = 0,
    kConnectionFisherServerPhaseWaitPing,
    kConnectionFisherServerPhaseWaitPayload,
    kConnectionFisherServerPhaseEstablished
} connectionfisherserver_phase_e;

typedef struct connectionfisherserver_tstate_s
{
    int unused;
} connectionfisherserver_tstate_t;

typedef struct connectionfisherserver_lstate_s
{
    connectionfisherserver_phase_e phase;
    bool                           next_init_sent;
    bool                           est_forwarded;
    bool                           dispatching;
    /* Holds older coalesced body across reply/Init and serializes nested input. */
    buffer_queue_t  pending_up;
    size_t          init_payload_bytes;
    buffer_stream_t in_stream;
} connectionfisherserver_lstate_t;

enum
{
    kConnectionFisherServerHandshakeLength   = 5,
    kConnectionFisherServerMaxHandshakeBytes = 4096,
    kConnectionFisherServerMaxPendingBytes   = 1024 * 1024,
    kTunnelStateSize                         = sizeof(connectionfisherserver_tstate_t),
    kLineStateSize                           = sizeof(connectionfisherserver_lstate_t)
};

WW_EXPORT tunnel_t    *connectionfisherserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t connectionfisherserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void connectionfisherserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void connectionfisherserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void connectionfisherserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void connectionfisherserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void connectionfisherserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void connectionfisherserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void connectionfisherserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void connectionfisherserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void connectionfisherserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void connectionfisherserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void connectionfisherserverLinestateInitialize(connectionfisherserver_lstate_t *ls, line_t *l);
void connectionfisherserverLinestateDestroy(connectionfisherserver_lstate_t *ls);

void connectionfisherserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void connectionfisherserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void connectionfisherserverCloseLineFromProtocolError(tunnel_t *t, line_t *l);
void connectionfisherserverHandleHandshakePayload(tunnel_t *t, line_t *l, sbuf_t *buf);
