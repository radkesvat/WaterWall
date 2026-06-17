#pragma once

#include "bufio/buffer_stream.h"
#include "wwapi.h"

typedef enum socks5client_protocol_e
{
    kSocks5ClientProtocolDestContext = 0,
    kSocks5ClientProtocolTcp = 1,
    kSocks5ClientProtocolUdp = 3
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
    kSocks5ClientLineKindUdpApp,
    kSocks5ClientLineKindUdpControl,
    kSocks5ClientLineKindUdpRelay
} socks5client_line_kind_t;

typedef struct socks5client_tstate_s
{
    address_context_t       target_addr;
    char                   *username;
    char                   *password;
    uint32_t                target_addr_source;
    uint32_t                target_port_source;
    socks5client_protocol_t protocol;
    uint8_t                 username_len;
    uint8_t                 password_len;
    bool                    verbose;
} socks5client_tstate_t;

typedef struct socks5client_lstate_s
{
    tunnel_t            *tunnel;
    line_t              *line;
    line_t              *app_line;
    line_t              *control_line;
    line_t              *udp_line;
    address_context_t    target_addr;
    address_context_t    relay_addr;
    buffer_stream_t      in_stream;
    buffer_queue_t       pending_up;
    socks5client_protocol_t protocol;
    socks5client_phase_t phase;
    socks5client_line_kind_t kind;
    bool                 udp_control_ready;
    bool                 udp_relay_ready;
} socks5client_lstate_t;

enum
{
    kTunnelStateSize               = sizeof(socks5client_tstate_t),
    kLineStateSize                 = sizeof(socks5client_lstate_t),
    kSocks5ClientPendingQueueCap   = 8,
    kSocks5ClientMaxPendingUpBytes = 1024 * 1024,
    kSocks5ClientMaxHandshakeBytes = 4096,
    kSocks5ClientUdpHeaderMaxLen   = 4 + 1 + UINT8_MAX + 2
};

WW_EXPORT void         socks5clientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *socks5clientTunnelCreate(node_t *node);
WW_EXPORT api_result_t socks5clientTunnelApi(tunnel_t *instance, sbuf_t *message);

void socks5clientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void socks5clientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void socks5clientTunnelOnPrepair(tunnel_t *t);
void socks5clientTunnelOnStart(tunnel_t *t);
void socks5clientTunnelOnStop(tunnel_t *t);

void socks5clientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void socks5clientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void socks5clientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void socks5clientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void socks5clientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void socks5clientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void socks5clientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void socks5clientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void socks5clientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void socks5clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void socks5clientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void socks5clientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void socks5clientLinestateInitialize(socks5client_lstate_t *ls, tunnel_t *t, line_t *l);
void socks5clientLinestateDestroy(socks5client_lstate_t *ls);

void socks5clientTunnelstateDestroy(socks5client_tstate_t *ts);
bool socks5clientApplyTargetContext(tunnel_t *t, line_t *l);
bool socks5clientSendGreeting(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientSendAuthRequest(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientSendConnectRequest(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientDrainHandshakeInput(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientStartUdpAssociation(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, bool *line_alive_out);
bool socks5clientForwardUdpAppPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf);
bool socks5clientHandleUdpRelayPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf);
void socks5clientOnUdpRelayEstablished(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
void socks5clientCloseOwnedLine(tunnel_t *t, line_t *owned_l);
void socks5clientCloseLineBidirectional(tunnel_t *t, line_t *l);
