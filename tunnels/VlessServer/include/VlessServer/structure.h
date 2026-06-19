#pragma once

#include "objects/user_handle.h"
#include "wwapi.h"

typedef enum vlessserver_line_kind_e
{
    kVlessServerLineKindNone = 0,
    kVlessServerLineKindClient,
    kVlessServerLineKindUdpRemote
} vlessserver_line_kind_t;

typedef enum vlessserver_phase_e
{
    kVlessServerPhaseIdle = 0,
    kVlessServerPhaseWaitInitial,
    kVlessServerPhaseFallback,
    kVlessServerPhaseTcpConnecting,
    kVlessServerPhaseTcpEstablished,
    kVlessServerPhaseUdpWaitPacket,
    kVlessServerPhaseUdpConnecting,
    kVlessServerPhaseUdpEstablished,
    kVlessServerPhaseClosing
} vlessserver_phase_t;

typedef enum vlessserver_close_origin_e
{
    kVlessServerCloseInternal = 0,
    kVlessServerCloseFromPrev,
    kVlessServerCloseFromNext
} vlessserver_close_origin_t;

typedef struct vlessserver_user_s
{
    uint8_t uuid[16];
    char   *username;
} vlessserver_user_t;

typedef struct vlessserver_tstate_s
{
    node_t   *auth_client_node;
    tunnel_t *auth_client_tunnel;

    node_t    user_controller_node;
    tunnel_t *user_controller_tunnel;

    node_t   *fallback_node;
    tunnel_t *fallback_tunnel;

    vlessserver_user_t *users;
    uint32_t            user_count;
    uint32_t            fallback_intentional_delay_ms;
    uint32_t            fallback_intentional_delay_jitter_ms;
    bool                allow_connect;
    bool                allow_udp;
    bool                verbose;
} vlessserver_tstate_t;

typedef struct vlessserver_lstate_s
{
    tunnel_t               *tunnel;
    line_t                 *line;
    line_t                 *client_line;
    line_t                 *udp_remote_line;
    address_context_t       udp_target;
    buffer_stream_t         in_stream;
    buffer_queue_t          pending_down;
    buffer_queue_t         *fallback_pending_up;
    user_handle_t           user_handle;
    char                   *auth_username; // resolved account name, owned (NULL if none)
    char                   *auth_password; // resolved raw password / UUID, owned (NULL if none)
    vlessserver_phase_t     phase;
    vlessserver_line_kind_t line_kind;
    bool                    client_line_locked;
    bool                    response_sent;
    bool                    user_handle_recorded;
    bool                    fallback_up_finish_pending;
    bool                    fallback_up_finished;
    bool                    fallback_delay_scheduled;
} vlessserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(vlessserver_tstate_t),
    kLineStateSize   = sizeof(vlessserver_lstate_t),

    kVlessServerUuidLen                = 16,
    kVlessServerCanonicalUuidStringLen = 36,
    kVlessServerResponseLen            = 2,
    kVlessServerUdpHeaderLen           = 2,
    kVlessServerUdpMaxPacket           = UINT16_MAX,
    kVlessServerBufferQueueCap         = 8,
    kVlessServerMaxInitialBytes        = 4096,
    kVlessServerMaxBufferedBytes       = 1024 * 1024,
    kVlessServerMaxPendingBytes        = 1024 * 1024,
    kVlessServerInitialMaxReqLen       = 1 + kVlessServerUuidLen + 1 + UINT8_MAX + 1 + 2 + 1 + 1 + UINT8_MAX
};

WW_EXPORT void         vlessserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *vlessserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t vlessserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void vlessserverTunnelOnPrepair(tunnel_t *t);
void vlessserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void vlessserverTunnelOnStart(tunnel_t *t);
void vlessserverTunnelOnStop(tunnel_t *t);

void vlessserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void vlessserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void vlessserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void vlessserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void vlessserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void vlessserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void vlessserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void vlessserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void vlessserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void vlessserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void vlessserverLinestateInitialize(vlessserver_lstate_t *ls, tunnel_t *t, line_t *l, vlessserver_line_kind_t kind);
void vlessserverLinestateDestroy(vlessserver_lstate_t *ls);
void vlessserverTunnelstateDestroy(vlessserver_tstate_t *ts);

bool vlessserverDrainInput(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, bool reject_short_password);
void vlessserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void vlessserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void vlessserverCloseLineBidirectional(tunnel_t *t, line_t *l);
void vlessserverOnSelectedEstablished(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls);
bool vlessserverWrapUdpPayload(line_t *l, sbuf_t **buf_io);
bool vlessserverSendFallbackPayload(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, sbuf_t *buf);
