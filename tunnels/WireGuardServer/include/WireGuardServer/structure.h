#pragma once

#include "AuthenticationClient/interface.h"
#include "UserController/interface.h"
#include "WireGuardCommon/dispatch.h"
#include "WireGuardCommon/engine.h"
#include "WireGuardCommon/prefix.h"
#include "WireGuardServer/interface.h"
#include "base/internal_types/list.h"

typedef struct ingress_s ingress_t;
typedef struct server_s  server_t;
typedef struct binding_s binding_t;

#define i_type binding_map_t
#define i_key  uint64_t
#define i_val  binding_t *
#include "stc/hmap.h"
#undef i_val
#undef i_key
#undef i_type

struct binding_s
{
    server_t                                      *server;
    wireguard_peer_t                              *peer;
    binding_t                                     *next, *previous;
    binding_t                                     *ingress_next, *ingress_previous;
    authenticationclient_wireguard_authorization_t authorization;
    ingress_t                                     *ingress;
    uint64_t                                       epoch;
    /* One plaintext packet for this binding and ingress. Guarded by bindings_lock. */
    sbuf_t  *pending;
    uint32_t pending_since;
    uint8_t  public_key[32];
    bool     usable, retiring;
};

struct ingress_s
{
    atomic_uint       references;
    wmutex_t          lock;
    line_t           *line;            /* Borrowed normal, created by the UDP ingress adapter. */
    ingress_t        *next, *previous; /* Owner-worker inventory. */
    binding_t        *binding_head;    /* Protected by the server's bindings_lock. */
    struct hlist_node orphan;          /* In the reclaimable or close-retry list, protected by bindings_lock. */
    ip_addr_t         ip;
    uint16_t          port;
    wid_t             worker;
    bool              paused;
    bool              awaiting_proof;
    atomic_bool       closing;
};

typedef struct server_line_s
{
    ingress_t *ingress;
} server_line_t;

struct server_s
{
    wireguard_device_t       engine;
    wireguard_dispatch_t     dispatch;
    tunnel_t                *tunnel;
    wmutex_t                 bindings_lock;
    binding_t               *binding_head, *provisional, *received_binding;
    binding_map_t            epochs;
    wireguard_prefix_table_t ranges;
    ingress_t              **ingress_heads;
    atomic_uint              ingress_count;
    struct hlist_head        orphan_ingresses, reclaim_batch;
    struct hlist_head        retry_closes, deferred_closes;
    unsigned                 unauthenticated_ingress; /* Protected by bindings_lock. */
    unsigned                 max_unauthenticated_ingress;
    size_t                   max_pending_rekey_bytes, pending_rekey_bytes;
    ingress_t               *receiving;
    bool                     has_pending;     /* Worker 0 hint. Detach may empty a slot before the next sweep. */
    const uint32_t          *releasing_since; /* Original age during synchronous owner-worker release. */
    wtimer_t                *timer;
    uint64_t                 next_epoch, reconciled_generation, receiving_generation;
    bool                     connection;
    node_t                  *auth_node;
    tunnel_t                *auth;
    node_t                   ptc_node, binding_node, controller_node;
    tunnel_t                *ptc, *binder, *controller;
};

/* Borrowed carrier lines and their owner-worker inventory. */
void wireguardserverIngressRetain(ingress_t *ingress);
void wireguardserverIngressRelease(void *argument);
bool wireguardserverReserveFreshIngress(server_t *state);
bool wireguardserverIngressAvailable(ingress_t *ingress, bool require_writable);
void wireguardserverCloseOrphanIngress(tunnel_t *t, line_t *line);
void wireguardserverRetryOrphanCloses(server_t *state);
void wireguardserverDetachIngress(tunnel_t *t, line_t *line);
void wireguardserverSetBindingIngress(binding_t *binding, ingress_t *ingress);

/* Peer identity, route ownership, and authorization. */
binding_t        *wireguardserverBindingByEpoch(server_t *state, uint64_t epoch);
bool              wireguardserverBindingCurrent(const binding_t *binding);
binding_t        *wireguardserverCreateBinding(server_t *state, wireguard_peer_t *peer,
                                               const authenticationclient_wireguard_authorization_t *authorization);
void              wireguardserverClearBinding(server_t *state, binding_t *binding);
void              wireguardserverRetireBinding(server_t *state, binding_t *binding);
uint64_t          wireguardserverSourceEpoch(void *context, const ip_addr_t *source);
bool              wireguardserverSameAuthorization(const authenticationclient_wireguard_authorization_t *a,
                                                   const authenticationclient_wireguard_authorization_t *b);
bool              wireguardserverBindingAuthorized(server_t *state, const binding_t *binding);
void              wireguardserverReconcile(server_t *state, bool periodic);
wireguard_peer_t *wireguardserverCandidate(void *context, const uint8_t public_key[32]);
bool              wireguardserverAuthenticated(void *context, wireguard_peer_t *peer);

/* Protocol output and packets held while a peer rekeys. */
bool wireguardserverOutput(void *context, sbuf_t *packet, wireguard_peer_t *selected_peer, const ip_addr_t *ip,
                           uint16_t port);
void wireguardserverInner(void *context, sbuf_t *packet, wireguard_peer_t *peer);
bool wireguardserverCanInitiate(void *context, wireguard_peer_t *peer);
void wireguardserverKeyUnavailable(void *context, sbuf_t *packet, wireguard_peer_t *peer);
void wireguardserverDiscardPending(binding_t *binding);
void wireguardserverSendHeldInner(server_t *state, sbuf_t *packet, uint64_t epoch, uint32_t since);
void wireguardserverServicePendingBinding(server_t *state, binding_t *binding);
void wireguardserverServicePending(server_t *state);

/* Connection-mode child pipeline. */
bool                          wireguardserverCreatePipeline(server_t *state, node_t *node);
void                          wireguardserverBindingInit(tunnel_t *t, line_t *line);
usercontroller_payload_mode_t wireguardserverPayloadMode(tunnel_t *owner, line_t *line);

void wireguardserverTick(wtimer_t *timer);
bool wireguardserverReadLimits(server_t *state, const cJSON *settings);
