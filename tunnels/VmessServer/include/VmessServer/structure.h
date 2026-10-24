#pragma once

#include "AuthenticationClient/interface.h"
#include "crypto.h"
#include "replay.h"
#include "wwapi.h"

typedef struct vmessserver_auth_runtime_s vmessserver_auth_runtime_t;
typedef struct vmessserver_auth_job_s     vmessserver_auth_job_t;

enum
{
    kVmessVersion                = 0x01,
    kVmessCmdTcp                 = 0x01,
    kVmessCmdUdp                 = 0x02,
    kVmessAtypIpv4               = 0x01,
    kVmessAtypDomain             = 0x02,
    kVmessAtypIpv6               = 0x03,
    kVmessServerInitialMaxReqLen = VMESS_REQUEST_PREFIX_SIZE + VMESS_REQUEST_HEADER_MAX + 16
};

typedef enum vmessserver_line_kind_e
{
    kVmessServerLineKindNone = 0,
    kVmessServerLineKindClient,
    kVmessServerLineKindUdpRemote
} vmessserver_line_kind_t;

typedef enum vmessserver_phase_e
{
    kVmessServerPhaseIdle = 0,
    kVmessServerPhaseWaitInitial,
    kVmessServerPhaseFallback,
    kVmessServerPhaseTcpConnecting,
    kVmessServerPhaseTcpEstablished,
    kVmessServerPhaseUdpConnecting,
    kVmessServerPhaseUdpEstablished,
    kVmessServerPhaseClosing
} vmessserver_phase_t;

typedef enum vmessserver_close_origin_e
{
    kVmessServerCloseInternal = 0,
    kVmessServerCloseFromPrev,
    kVmessServerCloseFromNext
} vmessserver_close_origin_t;

typedef enum vmessserver_auth_result_e
{
    kVmessServerAuthRejected = 0,
    kVmessServerAuthAccepted
} vmessserver_auth_result_t;

typedef struct vmessserver_user_s
{
    uint8_t uuid[16];
    char   *username;
} vmessserver_user_t;

typedef struct vmessserver_tstate_s
{
    vmessserver_auth_runtime_t *auth;
    vmess_replay_t             *replay;
    uint32_t                    handshake_timeout_ms;
    size_t                      auth_max_pending, auth_pending_max_bytes, auth_cache_max_bytes, replay_max_entries;
    node_t                     *auth_client_node;
    tunnel_t                   *auth_client_tunnel;

    node_t    user_controller_node;
    tunnel_t *user_controller_tunnel;

    node_t   *fallback_node;
    tunnel_t *fallback_tunnel;

    vmessserver_user_t *users;
    uint32_t            user_count;
    uint32_t            fallback_intentional_delay_ms;
    uint32_t            fallback_intentional_delay_jitter_ms;
    bool                allow_connect;
    bool                allow_udp;
    bool                verbose;
} vmessserver_tstate_t;

typedef struct vmessserver_lstate_s
{
    vmessserver_auth_job_t               *auth_job;
    authenticationclient_uuid_candidate_t candidate;
    uint64_t                              candidate_generation, auth_timestamp;
    vmess_prepared_key_t                  auth_key;
    vmess_request_header_t                request;
    vmess_body_ctx_t                      input_crypto, output_crypto;
    uint8_t                               response_header[VMESS_RESPONSE_HEADER_SIZE];
    uint8_t                               auth_result;
    bool                                  auth_recognized;
    bool                                  crypto_ready;
    bool                                  closing_output;
    bool                                  next_finished, prev_finished;
    bool                                  finish_pending;
    size_t                                unauth_bytes;
    uint32_t                              body_length;
    uint16_t                              request_length;
    sbuf_t                               *body_buffer;
    uint32_t                              body_filled;
    buffer_budget_reservation_t           input_reservation;
    buffer_budget_reservation_t           response_reservation;
    buffer_budget_reservation_t           body_reservation;
    tunnel_t                             *tunnel;
    line_t                               *line;
    line_t                               *client_line;
    line_t                               *udp_remote_line;
    address_context_t                     udp_target;
    buffer_queue_t                        pending_up;
    sbuf_t                               *input_head;
    size_t                                input_bytes;
    uint8_t                               header[kVmessServerInitialMaxReqLen];
    uint16_t                              header_filled;
    buffer_budget_t                       upstream_budget;
    buffer_budget_t                       response_budget;
    /* Response-header/reentry ordering only; direct ready replies are forwarded. */
    buffer_queue_t          pending_down;
    buffer_queue_t         *fallback_pending_up;
    user_handle_t           user_handle;
    char                   *auth_username; // resolved account name, owned (NULL if none)
    char                   *auth_password; // resolved raw password / UUID, owned (NULL if none)
    vmessserver_phase_t     phase;
    vmessserver_line_kind_t line_kind;

    /* Worker-owned dispatch, response and fallback flags share storage. */
    bool input_dispatching : 1;
    bool branch_initializing : 1;
    bool client_line_ref_held : 1;
    bool response_sent : 1;
    bool transport_est_sent : 1;
    bool response_dispatching : 1;
    /* Startup receiver-pressure replay and UDP producer control only. */
    bool response_paused : 1;
    /* Client-side upstream permission: current backend contribution and emitted hold. */
    bool udp_backend_paused : 1;
    bool udp_source_pause_sent : 1;
    bool fallback_close_draining : 1;
    bool fallback_branch_finished_during_drain : 1;
    bool fallback_delay_scheduled : 1;
} vmessserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(vmessserver_tstate_t),
    kLineStateSize   = sizeof(vmessserver_lstate_t),

    kVmessServerUuidLen                = 16,
    kVmessServerCanonicalUuidStringLen = 36,
    kVmessServerResponseLen            = VMESS_RESPONSE_HEADER_SIZE,
    kVmessServerUdpHeaderLen           = 2,
    kVmessServerUdpMaxPacket           = UINT16_MAX,
    kVmessServerBufferQueueCap         = 8,
    kVmessServerMaxBufferedBytes       = 2 * 1024 * 1024 + 65537,
    kVmessServerMaxPendingBytes        = 2 * 1024 * 1024,
    kVmessServerMaxPendingBuffers      = 1024
};
