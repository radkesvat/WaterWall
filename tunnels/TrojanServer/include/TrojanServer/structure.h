#pragma once

#include "address_codec.h"
#include "wwapi.h"

/* Each remote owns its immutable key; the client map borrows it until detach.
 * Routing context rewrites must never change lookup or removal identity. */
typedef struct trojanserver_remote_key_s
{
    trojanserver_address_t address;
    hash_t                 hash;
} trojanserver_remote_key_t;

static inline bool trojanserverRemoteKeyEqual(trojanserver_remote_key_t *const *left,
                                              trojanserver_remote_key_t *const *right)
{
    const trojanserver_address_t *a = &(*left)->address, *b = &(*right)->address;
    return a->kind == b->kind && a->port == b->port && a->length == b->length &&
           memoryEqual(a->bytes, b->bytes, a->length);
}

#define i_type trojanserver_remote_map_t
#define i_key  trojanserver_remote_key_t *
#define i_val  line_t *
#define i_eq   trojanserverRemoteKeyEqual
#ifdef TROJANSERVER_TEST_CONSTANT_HASH
#define i_hash(key) ((void) (key), UINT64_C(0))
#else
#define i_hash(key) ((*key)->hash)
#endif
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

typedef enum trojanserver_auth_result_e
{
    kTrojanServerAuthRejected = 0,
    kTrojanServerAuthAccepted,
    kTrojanServerAuthResourceFailure
} trojanserver_auth_result_t;

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

typedef struct trojanserver_lstate_s
{
    /* This state's line is either a borrowed client or an owned UDP backend. */
    tunnel_t                *tunnel;
    line_t                  *line;
    trojanserver_line_kind_t line_kind;
    trojanserver_phase_t     phase;
    trojanserver_branch_t    branch;

    /* The client pump serializes parser/branch-Init input and permission reentry. */
    bool pumping : 1;
    bool branch_initializing : 1;
    bool next_initialized : 1;
    bool next_established : 1;
    bool prev_est_sent : 1; // Est has been sent toward prev on the client line.

    /* Consumer permission is distinct from notifications sent to producers.
     * UDP keeps next_paused/next_pause_sent per backend and counts paused backends. */
    bool next_paused : 1;     // Next asked us to stop sending upstream payload.
    bool prev_paused : 1;     // Prev asked us to stop sending downstream payload.
    bool prev_pause_sent : 1; // We told prev to pause its upstream producer.
    bool next_pause_sent : 1; // We told next to pause its downstream producer.

    /* Parser, authentication and delayed-fallback flags use the same group. */
    bool first_payload_seen : 1;
    bool short_password : 1;
    bool frame_ready : 1;
    bool frame_selected : 1;
    bool user_handle_recorded : 1;
    bool fallback_delay_scheduled : 1;
    bool fallback_close_draining : 1;
    bool fallback_branch_finished_during_drain : 1;

    /* Client input: pending_up owns initial/UDP wire bytes, then opaque bytes
     * after CONNECT. The popped head remains owned here; input_bytes includes
     * queued input, the active head and the cached header while parsing. */
    buffer_budget_t   output_budget;
    buffer_queue_t    pending_up;
    sbuf_t           *input_head;
    size_t            input_bytes;
    uint8_t           header[320];
    uint16_t          header_filled;
    uint16_t          header_needed;
    uint16_t          body_length;

    /* The map owns backend lines; selected_remote borrows the current frame's
     * backend. Replies are framed and handed to the client synchronously. */
    trojanserver_remote_map_t udp_remote_lines;
    line_t                   *selected_remote;
    size_t                    paused_remotes;

    /* Backend-side association: holds a physical client reference through cleanup. */
    line_t                    *client_line;
    trojanserver_remote_key_t *remote_key;

    /* Authentication metadata; credential strings are owned and nullable. */
    user_handle_t user_handle;
    char         *auth_username;
    char         *auth_password;

    /* Intentional delay owns a real producer backlog. At zero delay this queue
     * only preserves branch-Init/reentry order within the active dispatch.
     * Source Finish admits at most one final upstream batch. */
    buffer_queue_t *fallback_pending_up;
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
    kTrojanServerMaxPendingBytes  = 2 * 1024 * 1024,
    kTrojanServerUdpHeaderMaxLen  = 1 + 1 + UINT8_MAX + 2 + 2 + 2,
    kTrojanServerMaxQueuedBuffers = 1024,
    kTrojanServerMaxWireBytes     = 2 * 1024 * 1024 + 8455
};
