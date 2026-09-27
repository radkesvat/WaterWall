#pragma once

#include "wwapi.h"

enum
{
    kVlessVersion    = 0x00,
    kVlessCmdTcp     = 0x01,
    kVlessCmdUdp     = 0x02,
    kVlessAtypIpv4   = 0x01,
    kVlessAtypDomain = 0x02,
    kVlessAtypIpv6   = 0x03
};

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

typedef enum vlessserver_auth_result_e
{
    kVlessServerAuthRejected = 0,
    kVlessServerAuthAccepted,
    kVlessServerAuthResourceFailure
} vlessserver_auth_result_t;

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
    tunnel_t         *tunnel;
    line_t           *line;
    line_t           *client_line;
    line_t           *udp_remote_line;
    address_context_t udp_target;
    buffer_queue_t    pending_up;
    sbuf_t           *input_head;
    size_t            input_bytes;
    uint8_t           header[278];
    uint16_t          header_filled;
    buffer_budget_t   upstream_budget;
    buffer_budget_t   response_budget;
    /* Response-header/reentry ordering only; direct ready replies are forwarded. */
    buffer_queue_t          pending_down;
    buffer_queue_t         *fallback_pending_up;
    user_handle_t           user_handle;
    char                   *auth_username; // resolved account name, owned (NULL if none)
    char                   *auth_password; // resolved raw password / UUID, owned (NULL if none)
    vlessserver_phase_t     phase;
    vlessserver_line_kind_t line_kind;

    /* Worker-owned dispatch, response and fallback flags share storage. */
    bool first_payload_seen : 1;
    bool input_dispatching : 1;
    bool branch_initializing : 1;
    bool client_line_ref_held : 1;
    bool response_sent : 1;
    bool transport_est_sent : 1;
    bool response_dispatching : 1;
    bool response_paused : 1;
    /* Client-side upstream permission: current backend contribution and emitted hold. */
    bool udp_backend_paused : 1;
    bool udp_source_pause_sent : 1;
    bool user_handle_recorded : 1;
    bool fallback_close_draining : 1;
    bool fallback_branch_finished_during_drain : 1;
    bool fallback_payload_paused : 1;
    bool fallback_delay_scheduled : 1;
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
    kVlessServerMaxBufferedBytes       = 2 * 1024 * 1024 + 65537,
    kVlessServerMaxPendingBytes        = 2 * 1024 * 1024,
    kVlessServerMaxPendingBuffers      = 1024,
    kVlessServerInitialMaxReqLen       = 23 + UINT8_MAX
};
