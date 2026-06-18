#pragma once

#include "wwapi.h"

#define i_type trojanserver_remote_map_t // NOLINT
#define i_key  hash_t                    // NOLINT
#define i_val  line_t *                  // NOLINT
#include "stc/hmap.h"

typedef enum trojanserver_line_kind_e
{
    kTrojanServerLineKindNone = 0,
    kTrojanServerLineKindClient,
    kTrojanServerLineKindUdpRemote
} trojanserver_line_kind_t;

typedef enum trojanserver_phase_e
{
    kTrojanServerPhaseIdle = 0,
    kTrojanServerPhaseWaitInitial,
    kTrojanServerPhaseFallback,
    kTrojanServerPhaseTcpConnecting,
    kTrojanServerPhaseTcpEstablished,
    kTrojanServerPhaseUdpWaitPacket,
    kTrojanServerPhaseUdpConnecting,
    kTrojanServerPhaseUdpEstablished,
    kTrojanServerPhaseClosing
} trojanserver_phase_t;

typedef enum trojanserver_branch_e
{
    kTrojanServerBranchNone = 0,
    kTrojanServerBranchTrojan,
    kTrojanServerBranchFallback
} trojanserver_branch_t;

typedef enum trojanserver_close_origin_e
{
    kTrojanServerCloseInternal = 0,
    kTrojanServerCloseFromPrev,
    kTrojanServerCloseFromNext
} trojanserver_close_origin_t;

typedef struct trojanserver_tstate_s
{
    node_t   *auth_client_node;
    tunnel_t *auth_client_tunnel;

    node_t    user_controller_node;
    tunnel_t *user_controller_tunnel;

    node_t   *fallback_node;
    tunnel_t *fallback_tunnel;

    bool allow_connect;
    bool allow_udp;
    bool verbose;
} trojanserver_tstate_t;

typedef struct trojanserver_lstate_s
{
    tunnel_t                 *tunnel;
    line_t                   *line;
    line_t                   *client_line;
    buffer_stream_t           in_stream;
    buffer_queue_t            pending_down;
    trojanserver_remote_map_t udp_remote_lines;
    user_handle_t             user_handle;
    char                     *auth_username; // resolved account name, owned (NULL if none)
    char                     *auth_password; // resolved raw password, owned (NULL if none)
    hash_t                    remote_key;
    trojanserver_phase_t      phase;
    trojanserver_line_kind_t  line_kind;
    trojanserver_branch_t     branch;
    bool                      client_line_locked;
    bool                      user_handle_recorded;
} trojanserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(trojanserver_tstate_t),
    kLineStateSize   = sizeof(trojanserver_lstate_t),

    kTrojanServerPasswordHexLen   = 56,
    kTrojanServerCrlfLen          = 2,
    kTrojanServerUdpMaxPacket     = 8192,
    kTrojanServerBufferQueueCap   = 8,
    kTrojanServerMaxInitialBytes  = 4096,
    kTrojanServerMaxPendingBytes  = 1024 * 1024,
    kTrojanServerUdpHeaderMaxLen  = 1 + 1 + UINT8_MAX + 2 + 2 + 2,
    kTrojanServerInitialMaxReqLen = 1 + 1 + 1 + UINT8_MAX + 2 + 2,
    kTrojanServerRemoteMapCap     = 8
};

WW_EXPORT void         trojanserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *trojanserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t trojanserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void trojanserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void trojanserverTunnelOnPrepair(tunnel_t *t);
void trojanserverTunnelOnStart(tunnel_t *t);
void trojanserverTunnelOnStop(tunnel_t *t);

void trojanserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void trojanserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind);
void trojanserverLinestateDestroy(trojanserver_lstate_t *ls);
void trojanserverTunnelstateDestroy(trojanserver_tstate_t *ts);

bool trojanserverDrainInput(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
void trojanserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void trojanserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void trojanserverCloseLineBidirectional(tunnel_t *t, line_t *l);
void trojanserverOnSelectedEstablished(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
bool trojanserverWrapUdpPayload(line_t *l, sbuf_t **buf_io);
