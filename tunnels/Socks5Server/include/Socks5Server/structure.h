#pragma once

#include "TcpUdpListener/interface.h"
#include "UdpListener/interface.h"
#include "wwapi.h"

#define i_type socks5server_remote_map_t // NOLINT
#define i_key  hash_t                    // NOLINT
#define i_val  line_t *                  // NOLINT
#include "stc/hmap.h"

typedef struct socks5server_assoc_entry_s
{
    uint64_t                              generation;
    wid_t                                 owner_wid;
    udplistener_dynamic_endpoint_handle_t dynamic_handle;
    uint16_t                              assigned_port;
    user_handle_t                         user_handle;
    char                                 *auth_username; // raw SOCKS5 username, owned (NULL if none)
    char                                 *auth_password; // raw SOCKS5 password, owned (NULL if none)
    bool                                  active;
} socks5server_assoc_entry_t;

#define i_type socks5server_assoc_map_t   // NOLINT
#define i_key  uint64_t                   // NOLINT
#define i_val  socks5server_assoc_entry_t // NOLINT
#include "stc/hmap.h"

typedef enum socks5server_line_kind_e
{
    kSocks5ServerLineKindNone = 0,
    kSocks5ServerLineKindControlTcp,
    kSocks5ServerLineKindUdpClient,
    kSocks5ServerLineKindUdpRemote,
    kSocks5ServerLineKindRejected
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

typedef enum socks5server_close_origin_e
{
    kSocks5ServerCloseInternal = 0, // we decided to close; close both directions
    kSocks5ServerCloseFromPrev,     // prev/downstream side finished us; close next only
    kSocks5ServerCloseFromNext      // next/upstream side finished us; close prev only
} socks5server_close_origin_t;

typedef struct socks5server_tstate_s
{
    node_t                        *auth_client_node;
    tunnel_t                      *auth_client_tunnel;
    node_t                         user_controller_node;
    tunnel_t                      *user_controller_tunnel;
    char                          *udp_reply_ipv4;
    ip_addr_t                      udp_reply_ip;
    bool                           allow_connect;
    bool                           allow_udp;
    bool                           no_auth;
    bool                           verbose;
    udplistener_dynamic_provider_t dynamic_provider;
    wid_t                          workers_count;
    socks5server_assoc_map_t      *worker_associations; // worker-local association map array
} socks5server_tstate_t;

typedef struct socks5server_lstate_s
{
    tunnel_t                             *tunnel;
    line_t                               *line;
    buffer_stream_t                       in_stream;
    buffer_queue_t                        pending_up;
    buffer_queue_t                        pending_down;
    socks5server_remote_map_t             udp_remote_lines;
    line_t                               *client_line;
    user_handle_t                         user_handle;
    char                                 *auth_username; // raw SOCKS5 username, owned (NULL if none)
    char                                 *auth_password; // raw SOCKS5 password, owned (NULL if none)
    hash_t                                remote_key;
    udplistener_dynamic_endpoint_handle_t dynamic_handle;
    socks5server_phase_t                  phase;
    socks5server_line_kind_t              kind;
    bool                                  connect_reply_sent;
    bool                                  client_line_ref_held;
    bool                                  user_handle_recorded;
    bool                                  udp_first_payload_validated;
    bool                                  prev_finished; // prev/downstream side already finished this control line
    bool                                  next_finished; // next/upstream side already finished this control line
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

WW_EXPORT void         socks5serverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *socks5serverTunnelCreate(node_t *node);
WW_EXPORT api_result_t socks5serverTunnelApi(tunnel_t *instance, sbuf_t *message);

void socks5serverTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void socks5serverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void socks5serverTunnelOnPrepair(tunnel_t *t);
void socks5serverTunnelOnStart(tunnel_t *t);
void socks5serverTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);

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

void socks5serverTunnelstateDestroy(socks5server_tstate_t *ts);
bool socks5serverResolveDynamicProvider(tunnel_t *t);
bool socks5serverControlDrainInput(tunnel_t *t, line_t *l, socks5server_lstate_t *ls);
void socks5serverOnControlEstablished(tunnel_t *t, line_t *l, socks5server_lstate_t *ls);
void socks5serverCloseControlLineFromUpstream(tunnel_t *t, line_t *l);
void socks5serverCloseControlLineFromDownstream(tunnel_t *t, line_t *l);
void socks5serverCloseControlLineBidirectional(tunnel_t *t, line_t *l);
void socks5serverCloseUdpClientLineFromUpstream(tunnel_t *t, line_t *client_l);
void socks5serverCloseUdpClientLine(tunnel_t *t, line_t *client_l);
void socks5serverCloseUdpRemoteLine(tunnel_t *t, line_t *remote_l);
bool socks5serverHandleUdpClientPayload(tunnel_t *t, line_t *l, socks5server_lstate_t *ls, sbuf_t *buf);
bool socks5serverWrapUdpPayloadForClient(line_t *l, sbuf_t **buf_io, const address_context_t *addr_ctx);
socks5server_assoc_entry_t *socks5serverFindWorkerAssociation(tunnel_t *t, wid_t wid, uint64_t generation);
bool    socks5serverAssociationIsActive(tunnel_t *t, wid_t wid, udplistener_dynamic_endpoint_handle_t handle,
                                        uint16_t assigned_port, socks5server_assoc_entry_t **entry_out);
bool    socks5serverValidateUdpClientAssociation(tunnel_t *t, line_t *l, socks5server_lstate_t *ls,
                                                 bool validate_provider_metadata);
void    socks5serverRejectUdpClientLine(tunnel_t *t, line_t *client_l);
void    socks5serverDetachRemoteFromClient(socks5server_lstate_t *remote_ls);
void    socks5serverUnregisterUdpAssociation(tunnel_t *t, socks5server_lstate_t *ls);
sbuf_t *socks5serverCreateCommandReply(line_t *l, uint8_t rep, const address_context_t *ctx);
void    socks5serverAssocEntryFreeCreds(socks5server_assoc_entry_t *entry);
void    socks5serverRecordLineUser(line_t *l, socks5server_lstate_t *ls, const user_handle_t *user_handle);
void    socks5serverRequireCurrentLineWorker(const line_t *l, const char *callback_name);
