#pragma once

#include "DomainResolver/interface.h"
#include "wwapi.h"

typedef enum socks5client_protocol_e
{
    kSocks5ClientProtocolDestContext = 0,
    kSocks5ClientProtocolTcp         = 1,
    kSocks5ClientProtocolUdp         = 3
} socks5client_protocol_t;

typedef enum socks5client_phase_e
{
    kSocks5ClientPhaseIdle = 0,
    kSocks5ClientPhaseWaitMethod,
    kSocks5ClientPhaseWaitAuth,
    kSocks5ClientPhaseWaitCommand,
    kSocks5ClientPhaseEstablished
} socks5client_phase_t;

typedef enum socks5client_line_kind_e
{
    kSocks5ClientLineKindDirect = 0,
    kSocks5ClientLineKindUdpApplication,
    kSocks5ClientLineKindUdpControl,
    kSocks5ClientLineKindUdpRelay
} socks5client_line_kind_t;

typedef struct socks5client_tstate_s
{
    node_t        domain_resolver_node;
    tunnel_t     *domain_resolver_tunnel;
    struct cJSON *domain_resolver_settings;

    address_context_t       target_addr;
    char                   *username;
    char                   *password;
    int                     domain_strategy;
    uint32_t                target_addr_source;
    uint32_t                target_port_source;
    socks5client_protocol_t protocol;
    uint8_t                 username_len;
    uint8_t                 password_len;
    bool                    verbose;
    bool                    resolve_domains;
} socks5client_tstate_t;

typedef struct socks5client_lstate_s
{
    tunnel_t                *tunnel;
    line_t                  *line;
    line_t                  *application_line;
    line_t                  *control_line;
    line_t                  *udp_line;
    address_context_t        target_addr;
    address_context_t        relay_addr;
    buffer_stream_t          in_stream;
    // Application FIFO retained only for SOCKS negotiation or an older deferred drain.
    buffer_budget_t          pending_budget;
    buffer_queue_t           pending_up;
    buffer_queue_t           pending_down; // Nested proxy input / deferred response FIFO.
    socks5client_protocol_t  protocol;
    socks5client_phase_t     phase;
    socks5client_line_kind_t kind;
    bool                     input_draining : 1;
    bool                     transport_est_forwarded : 1;
    bool                     greeting_due : 1;
    bool                     read_pause_sent : 1;
    bool                     next_paused : 1;
    bool                     prev_paused : 1;
    bool                     source_pause_sent : 1;
    bool                     draining_up : 1;
    bool                     udp_control_ready : 1;
    bool                     udp_relay_ready : 1;
} socks5client_lstate_t;

enum
{
    kTunnelStateSize               = sizeof(socks5client_tstate_t),
    kLineStateSize                 = sizeof(socks5client_lstate_t),
    kSocks5ClientMaxPendingUpBytes = 2U * 1024U * 1024U,
    kSocks5ClientMaxPendingDownBytes = 2U * 1024U * 1024U,
    kSocks5ClientMaxPendingBuffers = 1024,
    kSocks5ClientMaxHandshakeBytes = 4096,
    kSocks5ClientUdpHeaderMaxLen   = 4 + 1 + UINT8_MAX + 2
};

WW_EXPORT void         socks5clientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *socks5clientTunnelCreate(node_t *node);
WW_EXPORT api_result_t socks5clientTunnelApi(tunnel_t *instance, sbuf_t *message);

void socks5clientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void socks5clientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void socks5clientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void socks5clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void socks5clientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void socks5clientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void socks5clientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void socks5clientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void socks5clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void socks5clientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void socks5clientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool socks5clientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate);
