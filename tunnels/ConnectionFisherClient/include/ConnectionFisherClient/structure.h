#pragma once

#include "wwapi.h"

typedef enum connectionfisherclient_role_e
{
    kConnectionFisherClientRoleNone = 0,
    kConnectionFisherClientRoleMain,
    kConnectionFisherClientRoleChild
} connectionfisherclient_role_e;

typedef struct connectionfisherclient_tstate_s
{
    uint32_t simultaneous_tries_perline;
} connectionfisherclient_tstate_t;

typedef struct connectionfisherclient_lstate_s
{
    connectionfisherclient_role_e role;
    bool                          main_est_forwarded;
    bool                          child_handshake_complete;
    uint32_t                      child_slot;
    uint32_t                      child_count;
    uint32_t                      open_child_count;
    line_t                      **child_lines;
    line_t                       *selected_child;
    line_t                       *main_line;
    buffer_queue_t                pending_up;
    buffer_stream_t               read_stream;
} connectionfisherclient_lstate_t;

enum
{
    kConnectionFisherHandshakeLength   = 5,
    kConnectionFisherTimeoutMs         = 5000,
    kConnectionFisherMaxPendingUpBytes = 1024 * 1024,
    kConnectionFisherMaxHandshakeBytes = 4096,
    kConnectionFisherPendingQueueCap   = 8,
    kTunnelStateSize                   = sizeof(connectionfisherclient_tstate_t),
    kLineStateSize                     = sizeof(connectionfisherclient_lstate_t)
};

WW_EXPORT void         connectionfisherclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *connectionfisherclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t connectionfisherclientTunnelApi(tunnel_t *instance, sbuf_t *message);
void                   connectionfisherclientTunnelOnStop(tunnel_t *t);

void connectionfisherclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void connectionfisherclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void connectionfisherclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void connectionfisherclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void connectionfisherclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void connectionfisherclientLinestateInitializeMain(connectionfisherclient_lstate_t *ls, line_t *l,
                                                   uint32_t child_count);
void connectionfisherclientLinestateInitializeChild(connectionfisherclient_lstate_t *ls, line_t *l, line_t *main_l,
                                                    uint32_t slot);
void connectionfisherclientLinestateDestroyMain(connectionfisherclient_lstate_t *ls);
void connectionfisherclientLinestateDestroyChild(connectionfisherclient_lstate_t *ls);

bool connectionfisherclientSendPing(tunnel_t *t, line_t *child_l);
bool connectionfisherclientSelectChild(tunnel_t *t, line_t *child_l);
bool connectionfisherclientFlushPendingToSelected(tunnel_t *t, line_t *main_l, line_t *child_l);
void connectionfisherclientCloseMainLine(tunnel_t *t, line_t *main_l);
void connectionfisherclientCloseMainLineFromUpstream(tunnel_t *t, line_t *main_l);
void connectionfisherclientCloseChildLine(tunnel_t *t, line_t *child_l, bool force_close_main);
void connectionfisherclientCloseChildLineFromDownstream(tunnel_t *t, line_t *child_l, bool force_close_main);
void connectionfisherclientTimeoutTask(tunnel_t *t, line_t *main_l);
void connectionfisherclientHandleChildHandshakePayload(tunnel_t *t, line_t *child_l, sbuf_t *buf);
