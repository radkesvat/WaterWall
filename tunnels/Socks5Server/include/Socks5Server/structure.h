#pragma once

#include "wwapi.h"

#define i_type socks5server_remote_map_t // NOLINT
#define i_key  hash_t                    // NOLINT
#define i_val  line_t *                  // NOLINT
#include "stc/hmap.h"

// UDP association entry. This is metadata only: do not store or touch the TCP control line here,
// because UDP datagrams may be handled on a different worker than the control connection.
typedef struct socks5server_assoc_entry_s
{
    uint64_t      token;
    wid_t         owner_wid;
    user_handle_t user_handle;
} socks5server_assoc_entry_t;

#define i_type socks5server_assoc_map_t   // NOLINT
#define i_key  hash_t                     // NOLINT
#define i_val  socks5server_assoc_entry_t // NOLINT
#include "stc/hmap.h"

typedef enum socks5server_line_kind_e
{
    kSocks5ServerLineKindNone = 0,
    kSocks5ServerLineKindControlTcp,
    kSocks5ServerLineKindUdpClient,
    kSocks5ServerLineKindUdpRemote
} socks5server_line_kind_t;

typedef enum socks5server_phase_e
{
    kSocks5ServerPhaseIdle = 0,
    kSocks5ServerPhaseWaitMethod,
    kSocks5ServerPhaseWaitAuth,
    kSocks5ServerPhaseWaitRequest,
    kSocks5ServerPhaseConnectWaitEst,
    kSocks5ServerPhaseTcpEstablished,
    kSocks5ServerPhaseUdpControl,
    kSocks5ServerPhaseClosing
} socks5server_phase_t;

// Origin of a control-line teardown, so the close path never sends a callback back toward
// the side that already finished us (Waterwall directional-finish rule).
typedef enum socks5server_close_origin_e
{
    kSocks5ServerCloseInternal = 0, // we decided to close; close both directions
    kSocks5ServerCloseFromPrev,     // prev/downstream side finished us; close next only
    kSocks5ServerCloseFromNext      // next/upstream side finished us; close prev only
} socks5server_close_origin_t;

enum
{
    kSocks5ServerAssocShardCount      = 64,
    kSocks5ServerAssocShardInitialCap = 16
};

typedef struct socks5server_assoc_shard_s
{
    wrwlock_t                lock;
    socks5server_assoc_map_t map;
} socks5server_assoc_shard_t;

typedef struct socks5server_tstate_s
{
    node_t                    *auth_client_node;
    tunnel_t                  *auth_client_tunnel;
    node_t                     user_controller_node;
    tunnel_t                  *user_controller_tunnel;
    char                      *udp_reply_ipv4;
    ip_addr_t                  udp_reply_ip;
    atomic_ullong              next_association_token;
    bool                       allow_connect;
    bool                       allow_udp;
    bool                       no_auth;
    bool                       verbose;
    socks5server_assoc_shard_t assoc_shards[kSocks5ServerAssocShardCount];
} socks5server_tstate_t;

typedef struct socks5server_lstate_s
{
    tunnel_t                 *tunnel;
    line_t                   *line;
    buffer_stream_t           in_stream;
    buffer_queue_t            pending_up;
    buffer_queue_t            pending_down;
    socks5server_remote_map_t udp_remote_lines;
    line_t                   *client_line;
    user_handle_t             user_handle;
    hash_t                    remote_key;
    hash_t                    association_key;
    uint64_t                  association_token;
    socks5server_phase_t      phase;
    socks5server_line_kind_t  kind;
    bool                      connect_reply_sent;
    bool                      client_line_locked;
    bool                      user_handle_recorded;
    bool                      prev_finished; // prev/downstream side already finished this control line
    bool                      next_finished; // next/upstream side already finished this control line
} socks5server_lstate_t;

enum
{
    kTunnelStateSize               = sizeof(socks5server_tstate_t),
    kLineStateSize                 = sizeof(socks5server_lstate_t),
    kSocks5ServerBufferQueueCap    = 8,
    kSocks5ServerRemoteMapCap      = 8,
    kSocks5ServerMaxHandshakeBytes = 4096,
    kSocks5ServerMaxPendingBytes   = 1024 * 1024,
    kSocks5ServerUdpHeaderMaxLen   = 4 + 1 + UINT8_MAX + 2
};

WW_EXPORT void         socks5serverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *socks5serverTunnelCreate(node_t *node);
WW_EXPORT api_result_t socks5serverTunnelApi(tunnel_t *instance, sbuf_t *message);

void socks5serverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void socks5serverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void socks5serverTunnelOnPrepair(tunnel_t *t);
void socks5serverTunnelOnStart(tunnel_t *t);
void socks5serverTunnelOnStop(tunnel_t *t);

void socks5serverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void socks5serverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void socks5serverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void socks5serverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void socks5serverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void socks5serverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void socks5serverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void socks5serverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void socks5serverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void socks5serverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void socks5serverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void socks5serverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void socks5serverLinestateInitialize(socks5server_lstate_t *ls, tunnel_t *t, line_t *l, socks5server_line_kind_t kind);
void socks5serverLinestateDestroy(socks5server_lstate_t *ls);

void    socks5serverTunnelstateDestroy(socks5server_tstate_t *ts);
bool    socks5serverControlDrainInput(tunnel_t *t, line_t *l, socks5server_lstate_t *ls);
void    socks5serverOnControlEstablished(tunnel_t *t, line_t *l, socks5server_lstate_t *ls);
void    socks5serverCloseControlLineFromUpstream(tunnel_t *t, line_t *l);
void    socks5serverCloseControlLineFromDownstream(tunnel_t *t, line_t *l);
void    socks5serverCloseControlLineBidirectional(tunnel_t *t, line_t *l);
void    socks5serverCloseUdpClientLineFromUpstream(tunnel_t *t, line_t *client_l);
void    socks5serverCloseUdpClientLine(tunnel_t *t, line_t *client_l);
void    socks5serverCloseUdpRemoteLine(tunnel_t *t, line_t *remote_l);
bool    socks5serverHandleUdpClientPayload(tunnel_t *t, line_t *l, socks5server_lstate_t *ls, sbuf_t *buf);
bool    socks5serverWrapUdpPayloadForClient(line_t *l, sbuf_t **buf_io, const address_context_t *addr_ctx);
bool    socks5serverLookupUdpAssociation(tunnel_t *t, line_t *l, user_handle_t *user_handle_out, hash_t *key_out);
void    socks5serverDetachRemoteFromClient(socks5server_lstate_t *remote_ls);
void    socks5serverUnregisterUdpAssociation(tunnel_t *t, socks5server_lstate_t *ls);
sbuf_t *socks5serverCreateCommandReply(line_t *l, uint8_t rep, const address_context_t *ctx);
