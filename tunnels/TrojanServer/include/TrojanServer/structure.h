#pragma once

#include "splice_buffer.h"
#include "wwapi.h"

#define i_type trojanserver_remote_map_t // NOLINT
#define i_key  hash_t                    // NOLINT
#define i_val  line_t *                  // NOLINT
#include "stc/hmap.h"

/* Wire command and address tags shared by encoding and parsing. */
enum
{
    kTrojanCmdConnect      = 0x01,
    kTrojanCmdUdpAssociate = 0x03,
    kTrojanAtypIpv4        = 0x01,
    kTrojanAtypDomain      = 0x03,
    kTrojanAtypIpv6        = 0x04
};

typedef enum trojanserver_line_kind_e
{
    kTrojanServerLineKindNone = 0,
    kTrojanServerLineKindClient,
    kTrojanServerLineKindUdpRemote
} trojanserver_line_kind_t;

typedef enum trojanserver_phase_e
{
    kTrojanServerPhaseClosing = 0,
    kTrojanServerPhaseWaitInitial,
    kTrojanServerPhaseFallback,
    kTrojanServerPhaseTcpConnecting,
    kTrojanServerPhaseTcpEstablished,
    kTrojanServerPhaseUdpWaitPacket,
    kTrojanServerPhaseUdpConnecting,
    kTrojanServerPhaseUdpEstablished
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

typedef struct trojanserver_user_s
{
    uint8_t sha224[SHA224_DIGEST_SIZE];
    char   *username;
    char   *password;
} trojanserver_user_t;

typedef struct trojanserver_tstate_s
{
    node_t   *auth_client_node;
    tunnel_t *auth_client_tunnel;

    node_t    user_controller_node;
    tunnel_t *user_controller_tunnel;

    node_t   *fallback_node;
    tunnel_t *fallback_tunnel;

    trojanserver_user_t *users;
    uint32_t             user_count;
    uint32_t             fallback_intentional_delay_ms;
    uint32_t             fallback_intentional_delay_jitter_ms;
    bool                 allow_connect;
    bool                 allow_udp;
    bool                 verbose;
} trojanserver_tstate_t;

/* A non-NULL waiter denotes a reply received before this backend's Est.
 * Backend removal clears/discards all such entries before freeing its line. */
typedef struct trojanserver_reply_s
{
    struct trojanserver_reply_s *next;
    sbuf_t                      *buf;
    line_t                      *waiter;
} trojanserver_reply_t;

typedef struct trojanserver_lstate_s
{
    /* This state's line is either a borrowed client or an owned UDP backend. */
    tunnel_t                *tunnel;
    line_t                  *line;
    trojanserver_line_kind_t line_kind;
    trojanserver_phase_t     phase;
    trojanserver_branch_t    branch;

    /* Branch establishment and reentrancy. The main pump runs on the client. */
    bool pumping;
    bool branch_initializing;
    bool next_initialized;
    bool next_established;
    bool prev_est_sent; // Est has been sent toward prev on the client line.

    /* Consumer permission is distinct from notifications sent to producers.
     * UDP keeps next_paused/next_pause_sent per backend and counts paused backends. */
    bool next_paused;     // Next asked us to stop sending upstream payload.
    bool prev_paused;     // Prev asked us to stop sending downstream payload.
    bool prev_pause_sent; // We told prev to pause its upstream producer.
    bool next_pause_sent; // We told next to pause its downstream producer.

    /* Client input: pending_up owns initial/UDP wire bytes, then opaque bytes
     * after CONNECT. The popped head remains owned here; input_bytes includes
     * queued input, the active head and the cached header while parsing. */
    buffer_queue_t    pending_up;
    sbuf_t           *input_head;
    size_t            input_bytes;
    uint8_t           header[320];
    uint16_t          header_filled;
    uint16_t          header_needed;
    uint16_t          body_length;
    address_context_t frame_target;
    bool              first_payload_seen;
    bool              short_password;
    bool              frame_ready;
    bool              frame_selected;

    /* Owned TCP/fallback replies on the client; UDP uses the encoded FIFO below. */
    buffer_queue_t pending_down;

    /* Client-side UDP association: the map owns backend lines and selected_remote
     * borrows one of those lines. Encoded replies stay owned here until sent/discarded. */
    trojanserver_remote_map_t udp_remote_lines;
    line_t                   *selected_remote;
    size_t                    paused_remotes;
    trojanserver_reply_t     *reply_head;
    trojanserver_reply_t     *reply_tail;
    size_t                    reply_bytes;
    uint32_t                  reply_count;

    /* Backend-side association: holds a physical client reference through cleanup. */
    line_t *client_line;
    hash_t  remote_key;

    /* Authentication metadata; credential strings are owned and nullable. */
    user_handle_t user_handle;
    char         *auth_username;
    char         *auth_password;
    bool          user_handle_recorded;

    /* Client fallback owns the delayed replay queue. Reply draining is independent
     * of the main pump; source Finish admits at most one final upstream batch. */
    buffer_queue_t *fallback_pending_up;
    bool            fallback_delay_scheduled;
    bool            fallback_reply_pumping;
    bool            fallback_close_draining;
    bool            fallback_branch_finished_during_drain;
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
    kTrojanServerMaxQueuedBuffers = 1024,
    kTrojanServerMaxWireBytes     = 1024 * 1024 + 8455
};

WW_EXPORT void         trojanserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *trojanserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t trojanserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void trojanserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void trojanserverTunnelOnPrepair(tunnel_t *t);

void trojanserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void trojanserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind);
void trojanserverReleaseBuffers(trojanserver_lstate_t *ls);
void trojanserverLinestateDestroy(trojanserver_lstate_t *ls);
void trojanserverTunnelstateDestroy(trojanserver_tstate_t *ts);

void trojanserverPump(tunnel_t *t, line_t *l);
void trojanserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void trojanserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void trojanserverCloseLineBidirectional(tunnel_t *t, line_t *l);
void trojanserverOnNextEstablished(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
bool trojanserverWrapUdpPayload(line_t *l, sbuf_t **buf_io);
bool trojanserverSendFallbackPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, sbuf_t *buf);
bool trojanserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);

bool trojanserverIsUdp(const trojanserver_lstate_t *ls);
/* On success the queue owns *buf; on refusal the caller still owns it. */
bool trojanserverQueuePayload(buffer_queue_t *queue, sbuf_t **buf);
void trojanserverPumpFallbackReplies(tunnel_t *t, line_t *l, sbuf_t *buf);

void trojanserverSetNextPaused(tunnel_t *t, line_t *l, bool paused);

/* Shared implementation helpers; callbacks retain their directional admission. */
void      trojanserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp);
bool      trojanserverAuthenticateHash(tunnel_t *t, line_t *l, const uint8_t sha224[SHA224_DIGEST_SIZE],
                                       user_handle_t *user_handle_out);
void      trojanserverRecordLineUser(line_t *l, trojanserver_lstate_t *ls, const user_handle_t *user_handle);
tunnel_t *trojanserverSelectedUpstream(tunnel_t *t, const trojanserver_lstate_t *ls);
void      trojanserverResetHeader(trojanserver_lstate_t *ls);
bool      trojanserverRetainActiveHead(trojanserver_lstate_t *ls);
void      trojanserverParseInitial(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
bool      trojanserverDecodeUdp(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
void      trojanserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, tunnel_t *fallback);
void      trojanserverStartFallback(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
void      trojanserverSettleRemoteReplies(trojanserver_lstate_t *client, line_t *remote, bool established);
void      trojanserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next);
void      trojanserverCloseUdpRemoteLines(tunnel_t *t, trojanserver_lstate_t *client);
line_t   *trojanserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, trojanserver_lstate_t *client,
                                               const address_context_t *target);
bool      trojanserverNotifyRemotePermission(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
