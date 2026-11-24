#include "AuthenticationClient/interface.h"
#include "PacketsToConnection/interface.h"
#include "UserController/interface.h"
#include "WireGuardCommon/dispatch.h"
#include "WireGuardCommon/engine.h"
#include "WireGuardCommon/prefix.h"
#include "WireGuardServer/interface.h"
#include "base/internal_types/list.h"
#include "loggers/network_logger.h"

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
enum
{
    kPendingPacketChargeLimit         = 128U * 1024U,
    kDefaultMaxPendingRekeyBytes      = 4U * 1024U * 1024U,
    kIngressCloseRetriesPerTick       = 32,
    kDefaultMaxUnauthenticatedIngress = 1024
};
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

typedef struct send_s
{
    ingress_t *ingress;
    uint64_t   epoch;
} send_t;

static void ingressRetain(ingress_t *ingress)
{
    atomicAdd(&ingress->references, 1);
}
static void detachIngress(tunnel_t *t, line_t *line);

/* Only queued for a previously authenticated ingress with no remaining binding. */
static void closeOrphanIngress(tunnel_t *t, line_t *line)
{
    server_line_t *ls = lineGetState(line, t);
    if (ls->ingress == NULL)
        return;
    detachIngress(t, line);
    tunnelPrevDownStreamFinish(t, line);
}

/* bindings_lock pins the borrowed line until scheduling takes its own reference.
 * Worker Stop drains the owner inventory if shutdown cancels an accepted close. */
static bool scheduleOrphanClose(server_t *state, ingress_t *ingress)
{
    const bool queued =
        lineScheduleTask(ingress->line, closeOrphanIngress, state->tunnel, NULL) == kLineTaskSubmitAcceptedAsync;
    /* A failed replacement leaves a charged orphan available for another proof.
     * A demotion with no slot must close admission even if its worker is stopping. */
    atomicStore(&ingress->closing, queued || ! ingress->awaiting_proof);
    return queued;
}

/* Try one charged endpoint per arrival. Finish this batch before revisiting
 * refusals or endpoints that lost their last binding in the meantime. */
static bool reclaimIngressSlot(server_t *state)
{
    if (hlist_empty(&state->reclaim_batch))
        hlist_move_list(&state->orphan_ingresses, &state->reclaim_batch);
    if (hlist_empty(&state->reclaim_batch))
        return false;

    ingress_t *orphan = hlist_entry(state->reclaim_batch.first, ingress_t, orphan);
    hlist_del_init(&orphan->orphan);
    if (! scheduleOrphanClose(state, orphan))
    {
        hlist_add_head(&orphan->orphan, &state->orphan_ingresses);
        return false;
    }
    /* The new ingress takes over the old charge. */
    orphan->awaiting_proof = false;
    return true;
}

static bool reserveFreshIngress(server_t *state)
{
    mutexLock(&state->bindings_lock);
    bool accepted = state->unauthenticated_ingress < state->max_unauthenticated_ingress;
    if (accepted)
        ++state->unauthenticated_ingress;
    else
        accepted = reclaimIngressSlot(state);
    mutexUnlock(&state->bindings_lock);
    return accepted;
}

/* First proof and line detach both settle their charge under bindings_lock. */
static void releaseIngressCharge(server_t *state, ingress_t *ingress)
{
    hlist_del_init(&ingress->orphan);
    if (ingress->awaiting_proof)
    {
        assert(state->unauthenticated_ingress != 0);
        --state->unauthenticated_ingress;
        ingress->awaiting_proof = false;
    }
}

static void ingressDetachBinding(server_t *state, ingress_t *ingress)
{
    if (ingress->binding_head != NULL || ingress->line == NULL || atomicLoad(&ingress->closing) ||
        ingress->awaiting_proof)
        return;
    if (state->unauthenticated_ingress < state->max_unauthenticated_ingress)
    {
        ++state->unauthenticated_ingress;
        ingress->awaiting_proof = true;
        hlist_add_head(&ingress->orphan, &state->orphan_ingresses);
    }
    else if (! scheduleOrphanClose(state, ingress))
        hlist_add_head(&ingress->orphan, &state->deferred_closes);
}

/* A refused owner submission has no queued task. Retry a bounded share each
 * tick, finishing the current batch before revisiting failures and new arrivals. */
static void retryOrphanCloses(server_t *state)
{
    mutexLock(&state->bindings_lock);
    if (hlist_empty(&state->retry_closes))
        hlist_move_list(&state->deferred_closes, &state->retry_closes);
    for (unsigned i = 0; i < kIngressCloseRetriesPerTick && ! hlist_empty(&state->retry_closes); ++i)
    {
        ingress_t *ingress = hlist_entry(state->retry_closes.first, ingress_t, orphan);
        hlist_del_init(&ingress->orphan);
        if (! scheduleOrphanClose(state, ingress))
            hlist_add_head(&ingress->orphan, &state->deferred_closes);
    }
    mutexUnlock(&state->bindings_lock);
}

/* Pending packets are admitted and released under bindings_lock. */
static bool chargePending(server_t *state, const sbuf_t *packet)
{
    const size_t charge = sbufGetAllocationCharge(packet);
    if (charge > kPendingPacketChargeLimit || charge > state->max_pending_rekey_bytes - state->pending_rekey_bytes)
        return false;
    state->pending_rekey_bytes += charge;
    return true;
}

static void unchargePending(server_t *state, const sbuf_t *packet)
{
    const size_t charge = sbufGetAllocationCharge(packet);
    assert(charge <= state->pending_rekey_bytes);
    state->pending_rekey_bytes -= charge;
}
/* When both gates are needed, take bindings_lock before the ingress lock. */
static bool ingressAvailable(ingress_t *ingress, bool require_writable)
{
    mutexLock(&ingress->lock);
    const bool available =
        ingress->line != NULL && ! atomicLoad(&ingress->closing) && (! require_writable || ! ingress->paused);
    mutexUnlock(&ingress->lock);
    return available;
}
static void ingressRelease(void *argument)
{
    ingress_t *ingress = argument;
    if (ingress != NULL && atomicSub(&ingress->references, 1) == 1)
    {
        assert(ingress->line == NULL);
        mutexDestroy(&ingress->lock);
        memoryFree(ingress);
    }
}
static void releaseSend(void *argument)
{
    send_t *send = argument;
    ingressRelease(send->ingress);
    memoryFree(send);
}
static bool sameAuthorization(const authenticationclient_wireguard_authorization_t *a,
                              const authenticationclient_wireguard_authorization_t *b)
{
    return a->handle.user_id == b->handle.user_id && a->continuity == b->continuity &&
           a->handle.generation >= b->handle.generation && ipAddrCmp(&a->network, &b->network) &&
           ipAddrCmp(&a->mask, &b->mask);
}
/* Access under bindings_lock on foreign workers. Never retain the result across an unlock there. */
static binding_t *bindingByEpoch(server_t *state, uint64_t epoch)
{
    const binding_map_t_value *entry = binding_map_t_get(&state->epochs, epoch);
    return entry == NULL ? NULL : entry->second;
}

static bool bindingCurrent(const binding_t *binding)
{
    return binding != NULL && binding->usable && ! binding->retiring;
}
/* Owner-worker check, including cached eligibility while new admissions are closed. */
static bool bindingAuthorized(server_t *state, const binding_t *binding)
{
    return authenticationclientWireGuardAuthorizationMatches(state->auth,
                                                             binding->public_key,
                                                             &binding->authorization.handle,
                                                             binding->authorization.continuity,
                                                             &binding->authorization.network,
                                                             &binding->authorization.mask);
}
/* All pending buffer and ingress membership changes hold bindings_lock. */
static sbuf_t *takePending(binding_t *binding)
{
    sbuf_t *packet = binding->pending;
    if (packet != NULL)
    {
        unchargePending(binding->server, packet);
        binding->pending = NULL;
    }
    return packet;
}

static void discardPending(binding_t *binding)
{
    sbuf_t *packet = takePending(binding);
    if (packet != NULL)
        sbufDestroy(packet); /* The producer may own a different worker's pool. */
}

static void setBindingIngress(binding_t *binding, ingress_t *ingress)
{
    ingress_t *old = binding->ingress;
    if (old == ingress)
        return;
    if (old != NULL)
    {
        discardPending(binding);
        if (binding->ingress_previous != NULL)
            binding->ingress_previous->ingress_next = binding->ingress_next;
        else
            old->binding_head = binding->ingress_next;
        if (binding->ingress_next != NULL)
            binding->ingress_next->ingress_previous = binding->ingress_previous;
        ingressDetachBinding(binding->server, old);
        ingressRelease(old);
    }
    binding->ingress          = ingress;
    binding->ingress_previous = binding->ingress_next = NULL;
    if (ingress != NULL)
    {
        ingressRetain(ingress);
        binding->ingress_next = ingress->binding_head;
        if (binding->ingress_next != NULL)
            binding->ingress_next->ingress_previous = binding;
        ingress->binding_head = binding;
        releaseIngressCharge(binding->server, ingress);
    }
}

static uint64_t sourceEpoch(void *context, const ip_addr_t *source)
{
    server_t *state = context;
    if (UNLIKELY(! atomicLoad(&state->dispatch.open)) || ! IP_IS_V4(source))
        return 0;
    uint8_t                                        key[32];
    authenticationclient_wireguard_authorization_t expected = {0};
    mutexLock(&state->bindings_lock);
    const binding_t *binding = wireguardPrefixLookup(&state->ranges, source);
    if (! bindingCurrent(binding))
    {
        mutexUnlock(&state->bindings_lock);
        return 0;
    }
    const uint64_t epoch = binding->epoch;
    expected.handle      = binding->authorization.handle;
    expected.network     = binding->authorization.network;
    expected.mask        = binding->authorization.mask;
    expected.continuity  = binding->authorization.continuity;
    memoryCopy(key, binding->public_key, sizeof(key));
    mutexUnlock(&state->bindings_lock);
    if (! authenticationclientWireGuardAuthorizationMatches(
            state->auth, key, &expected.handle, expected.continuity, &expected.network, &expected.mask))
        return 0;
    mutexLock(&state->bindings_lock);
    const bool live = bindingCurrent(bindingByEpoch(state, epoch));
    mutexUnlock(&state->bindings_lock);
    return live ? epoch : 0;
}

/* The range owner must stay unique even if the engine reuses a retired peer's ID. */
static size_t rangeOwner(const binding_t *binding)
{
    return (size_t) (uintptr_t) binding;
}

static binding_t *createBinding(server_t *state, wireguard_peer_t *peer,
                                const authenticationclient_wireguard_authorization_t *authorization)
{
    binding_t *binding = memoryAllocateZero(sizeof(*binding));
    binding->server    = state;
    binding->peer      = peer;
    memoryCopy(binding->public_key, peer->public_key, sizeof(binding->public_key));
    if (authorization != NULL)
        binding->authorization = *authorization;
    mutexLock(&state->bindings_lock);
    binding->epoch                = state->next_epoch + 1;
    binding_map_t_result inserted = binding_map_t_insert(&state->epochs, binding->epoch, binding);
    if (UNLIKELY(binding->epoch == 0 || (inserted.ref != NULL && ! inserted.inserted)))
    {
        LOGF("WireGuardServer: binding epoch exhausted or duplicated");
        abortProgramNow(1);
    }
    if (inserted.ref == NULL)
    {
        mutexUnlock(&state->bindings_lock);
        memoryFree(binding);
        return NULL;
    }
    for (unsigned i = 0; i < WIREGUARD_MAX_SRC_IPS; ++i)
    {
        const wireguard_allowed_ip_t *range = &peer->allowed_source_ips[i];
        if (range->valid &&
            ! wireguardPrefixInsert(&state->ranges, &range->ip, &range->mask, rangeOwner(binding), binding, true))
        {
            for (unsigned j = 0; j < i; ++j)
            {
                range = &peer->allowed_source_ips[j];
                if (range->valid)
                    wireguardPrefixRemove(&state->ranges, &range->ip, &range->mask, rangeOwner(binding));
            }
            binding_map_t_erase(&state->epochs, binding->epoch);
            mutexUnlock(&state->bindings_lock);
            memoryFree(binding);
            return NULL;
        }
    }
    state->next_epoch = binding->epoch;
    binding->next     = state->binding_head;
    if (binding->next != NULL)
        binding->next->previous = binding;
    state->binding_head = binding;
    peer->context       = binding;
    mutexUnlock(&state->bindings_lock);
    return binding;
}

static void clearBinding(server_t *state, binding_t *binding)
{
    mutexLock(&state->bindings_lock);
    if (state->connection)
        wireguardPrefixRemove(
            &state->ranges, &binding->authorization.network, &binding->authorization.mask, rangeOwner(binding));
    else
        for (unsigned i = 0; i < WIREGUARD_MAX_SRC_IPS; ++i)
        {
            const wireguard_allowed_ip_t *range = &binding->peer->allowed_source_ips[i];
            if (range->valid)
                wireguardPrefixRemove(&state->ranges, &range->ip, &range->mask, rangeOwner(binding));
        }
    binding_map_t_erase(&state->epochs, binding->epoch);
    if (binding->previous != NULL)
        binding->previous->next = binding->next;
    else
        state->binding_head = binding->next;
    if (binding->next != NULL)
        binding->next->previous = binding->previous;
    if (state->provisional == binding)
        state->provisional = NULL;
    if (state->received_binding == binding)
        state->received_binding = NULL;
    discardPending(binding);
    setBindingIngress(binding, NULL);
    mutexUnlock(&state->bindings_lock);
    if (binding->peer != NULL)
        discard wireguardifRemovePeer(&state->engine, binding->peer->id);
    authenticationclientWireGuardAuthorizationClear(&binding->authorization);
    memoryFree(binding);
}

static void retired(void *context, bool success)
{
    /* Failed and canceled work can notify from any thread. Successful completion
     * executes on the coordinator after all owners have drained the range. */
    if (success)
    {
        assert(currentThreadOwnsWorker(0));
        binding_t *binding = context;
        clearBinding(binding->server, binding);
    }
}

static void retireBinding(server_t *state, binding_t *binding)
{
    if (binding->retiring)
        return;
    if (! binding->usable)
    {
        clearBinding(state, binding);
        return;
    }
    mutexLock(&state->bindings_lock);
    binding->usable   = false;
    binding->retiring = true;
    discardPending(binding);
    setBindingIngress(binding, NULL);
    mutexUnlock(&state->bindings_lock);
    discard wireguardifRemovePeer(&state->engine, binding->peer->id);
    binding->peer = NULL;
    ptcRetireSourceRange(
        state->ptc, &binding->authorization.network, &binding->authorization.mask, 0, retired, binding);
}

static void reconcile(server_t *state, bool periodic)
{
    if (! state->connection)
        return;
    const uint64_t generation = authenticationclientUsersGeneration(state->auth);
    if (! periodic && state->reconciled_generation == generation)
        return;
    state->reconciled_generation = generation;
    for (binding_t *binding = state->binding_head, *next; binding != NULL; binding = next)
    {
        next = binding->next;
        if (binding->retiring || (! periodic && binding->authorization.generation == generation))
            continue;
        /* Local usage and time can revoke an idle account without a table update. */
        if (! binding->usable || ! bindingAuthorized(state, binding))
            retireBinding(state, binding);
        else
            binding->authorization.generation = generation;
    }
}

static wireguard_peer_t *candidate(void *context, const uint8_t public_key[32])
{
    server_t         *state = context;
    wireguard_peer_t *peer  = peerLookupByPubkey(&state->engine, public_key);
    if (peer != NULL)
    {
        binding_t *binding = peer->context;
        if (binding->authorization.continuity > state->receiving_generation)
            return NULL;
        if (bindingCurrent(binding) && bindingAuthorized(state, binding))
            return peer;
        retireBinding(state, binding);
        return NULL;
    }
    authenticationclient_wireguard_authorization_t authorization = {0};
    if (authenticationclientCopyWireGuardAuthorization(state->auth, public_key, &authorization) !=
            kAuthenticationClientUserLookupOk ||
        ! IP_IS_V4(&authorization.network) || authorization.continuity > state->receiving_generation ||
        authorization.generation != authenticationclientUsersGeneration(state->auth))
        goto reject;
    /* Protected inner Init acquires the current profile when it publishes the flow. */
    authenticationclientUserProfileClear(&authorization.profile);
    peer = wireguardPeerCreate(&state->engine, public_key, NULL);
    if (peer == NULL)
        goto reject;
    if (wireguardifAddAllowedIp(&state->engine, peer->id, &authorization.network, &authorization.mask) == ERR_OK)
    {
        state->provisional = createBinding(state, peer, &authorization);
        if (state->provisional != NULL)
            return peer;
    }
    discard wireguardifRemovePeer(&state->engine, peer->id);
reject:
    authenticationclientWireGuardAuthorizationClear(&authorization);
    return NULL;
}

static bool authenticated(void *context, wireguard_peer_t *peer)
{
    server_t      *state   = context;
    binding_t     *binding = peer->context;
    if (UNLIKELY(state->connection && binding->authorization.continuity > state->receiving_generation))
        return false;
    if (state->connection)
    {
        bool valid;
        if (binding->usable && ! binding->retiring)
            valid =
                binding->authorization.continuity <= state->receiving_generation && bindingAuthorized(state, binding);
        else
        {
            authenticationclient_wireguard_authorization_t authorization = {0};
            valid = authenticationclientCopyWireGuardAuthorization(state->auth, peer->public_key, &authorization) ==
                        kAuthenticationClientUserLookupOk &&
                    sameAuthorization(&authorization, &binding->authorization) &&
                    authorization.generation == authenticationclientUsersGeneration(state->auth);
            authenticationclientWireGuardAuthorizationClear(&authorization);
        }
        if (UNLIKELY(! valid))
        {
            retireBinding(state, binding);
            return false;
        }
    }
    if (UNLIKELY(binding->retiring || state->receiving == NULL))
        return false;
    mutexLock(&state->bindings_lock);
    if (state->receiving->line == NULL || atomicLoad(&state->receiving->closing))
    {
        mutexUnlock(&state->bindings_lock);
        return false;
    }
    setBindingIngress(binding, state->receiving);
    binding->usable = true;
    mutexUnlock(&state->bindings_lock);
    state->received_binding = binding;
    if (state->provisional == binding)
        state->provisional = NULL;
    return true;
}

static void sendOnIngress(tunnel_t *t, sbuf_t *packet, void *argument)
{
    server_t *state = tunnelGetState(t);
    send_t   *send  = argument;
    if (send->epoch != 0)
    {
        authenticationclient_wireguard_authorization_t expected = {0};
        uint8_t                                        key[32]  = {0};
        mutexLock(&state->bindings_lock);
        const binding_t *binding = bindingByEpoch(state, send->epoch);
        bool             valid   = bindingCurrent(binding);
        if (valid && state->connection)
        {
            expected.handle     = binding->authorization.handle;
            expected.network    = binding->authorization.network;
            expected.mask       = binding->authorization.mask;
            expected.continuity = binding->authorization.continuity;
            memoryCopy(key, binding->public_key, sizeof(key));
        }
        mutexUnlock(&state->bindings_lock);
        if (valid && state->connection)
            valid = authenticationclientWireGuardAuthorizationMatches(
                state->auth, key, &expected.handle, expected.continuity, &expected.network, &expected.mask);
        mutexLock(&state->bindings_lock);
        valid = valid && bindingCurrent(bindingByEpoch(state, send->epoch));
        mutexUnlock(&state->bindings_lock);
        if (UNLIKELY(! valid))
        {
            sbufDestroy(packet);
            return;
        }
    }
    ingress_t *ingress = send->ingress;
    mutexLock(&ingress->lock);
    line_t    *line     = ingress->line;
    /* Admission checked Pause before posting. A later Pause leaves this accepted datagram in flight. */
    if (line != NULL)
        lineRef(line);
    mutexUnlock(&ingress->lock);
    if (line == NULL)
    {
        sbufDestroy(packet);
        return;
    }
    tunnelPrevDownStreamPayload(t, line, packet);
    lineUnref(line);
}
static bool output(void *context, sbuf_t *packet, wireguard_peer_t *selected_peer, const ip_addr_t *ip, uint16_t port)
{
    server_t  *state    = context;
    ingress_t *ingress  = NULL;
    send_t     snapshot = {0};
    if (selected_peer != NULL && selected_peer->valid)
    {
        binding_t *binding = selected_peer->context;
        if (bindingCurrent(binding) && ipAddrCmp(&selected_peer->ip, ip) && selected_peer->port == port)
        {
            ingress        = binding->ingress;
            snapshot.epoch = binding->epoch;
        }
    }
    if (ingress == NULL && state->receiving != NULL && ipAddrCmp(&state->receiving->ip, ip) &&
        state->receiving->port == port)
        ingress = state->receiving;
    if (ingress == NULL || ! ingressAvailable(ingress, true))
    {
        /* In-place encryption can preserve an inner producer's original allocation. */
        sbufDestroy(packet);
        return false;
    }
    send_t *send  = memoryAllocate(sizeof(*send));
    *send         = snapshot;
    send->ingress = ingress;
    ingressRetain(ingress);
    return wireguardDispatch(
        &state->dispatch, ingress->worker, state->tunnel, packet, send, sendOnIngress, releaseSend);
}
static void inner(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = peer->context;
    if (UNLIKELY(! bindingCurrent(binding)))
    {
        reuseBuffer(packet);
        return;
    }
    line_t *line = tunnelchainGetWorkerPacketLine(state->tunnel->chain, 0);
    tunnelNextUpStreamPayload(state->tunnel, line, packet);
}

/* Recheck eligibility on every locally generated initiation, including timeout retries. */
static bool canInitiate(void *context, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = peer->context;
    if (bindingCurrent(binding) && binding->ingress != NULL && ingressAvailable(binding->ingress, false) &&
        (! state->connection || bindingAuthorized(state, binding)))
        return true;
    mutexLock(&state->bindings_lock);
    discardPending(binding);
    mutexUnlock(&state->bindings_lock);
    return false;
}

static void keyUnavailable(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = peer->context;
    bool       demand  = false;
    mutexLock(&state->bindings_lock);
    ingress_t *ingress = binding->ingress;
    if (bindingCurrent(binding) && ingress != NULL && ingressAvailable(ingress, false))
    {
        const uint32_t now = getTickMS();
        if (binding->pending != NULL && now - binding->pending_since >= REKEY_ATTEMPT_TIME * 1000U)
            discardPending(binding);
        const uint32_t since = state->releasing_since != NULL ? *state->releasing_since : now;
        demand               = binding->pending == NULL && now - since < REKEY_ATTEMPT_TIME * 1000U;
        if (demand && chargePending(state, packet))
        {
            state->has_pending     = true;
            binding->pending       = packet;
            binding->pending_since = since;
            packet                 = NULL;
        }
    }
    mutexUnlock(&state->bindings_lock);
    if (packet != NULL)
        sbufDestroy(packet);
    if (demand)
        wireguardCommonRequestHandshake(&state->engine, peer);
}

static void sendInner(tunnel_t *t, sbuf_t *packet, void *argument);

static void sendHeldInner(server_t *state, sbuf_t *packet, uint64_t epoch, uint32_t since)
{
    /* All other inner deliveries are force-queued. Only this packet can lose its key and reenter keyUnavailable. */
    assert(state->releasing_since == NULL);
    state->releasing_since = &since;
    sendInner(state->tunnel, packet, &epoch);
    state->releasing_since = NULL;
}

/* The captured epoch is revalidated by the ordinary reverse packet path before encryption. */
static void servicePendingBinding(server_t *state, binding_t *binding)
{
    mutexLock(&state->bindings_lock);
    sbuf_t *packet = binding->pending;
    if (packet != NULL)
    {
        if (wireguardExpired(binding->pending_since, REKEY_ATTEMPT_TIME))
            discardPending(binding);
        else if (wireguardCommonPeerCanSend(binding->peer) && ingressAvailable(binding->ingress, true))
        {
            const uint64_t epoch = binding->epoch;
            const uint32_t since = binding->pending_since;
            packet               = takePending(binding);
            mutexUnlock(&state->bindings_lock);
            sendHeldInner(state, packet, epoch, since);
            return;
        }
        else
            state->has_pending = true;
    }
    mutexUnlock(&state->bindings_lock);
}

static void servicePending(server_t *state)
{
    if (! state->has_pending)
        return;
    state->has_pending = false;
    for (binding_t *binding = state->binding_head; binding != NULL; binding = binding->next)
        servicePendingBinding(state, binding);
}

typedef struct receive_s
{
    ingress_t *ingress;
    uint64_t   generation;
} receive_t;
static void releaseReceive(void *argument)
{
    receive_t *received = argument;
    ingressRelease(received->ingress);
    memoryFree(received);
}
static void receive(tunnel_t *t, sbuf_t *packet, void *argument)
{
    server_t  *state    = tunnelGetState(t);
    receive_t *received = argument;
    ingress_t *ingress  = received->ingress;
    reconcile(state, false);
    if (UNLIKELY(! ingressAvailable(ingress, false)))
    {
        reuseBuffer(packet);
        return;
    }
    state->received_binding     = NULL;
    state->receiving            = ingress;
    state->receiving_generation = received->generation;
    wireguardCommonReceive(&state->engine, packet, &ingress->ip, ingress->port);
    state->receiving            = NULL;
    state->receiving_generation = 0;
    if (state->received_binding != NULL)
        servicePendingBinding(state, state->received_binding);
    state->received_binding = NULL;
    /* The sole provisional candidate belongs to this owner's synchronous receive. */
    if (state->provisional != NULL)
        clearBinding(state, state->provisional);
}
static void payloadUp(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    server_t      *state = tunnelGetState(t);
    server_line_t *ls    = lineGetState(line, t);
    if (UNLIKELY(ls->ingress == NULL))
    {
        lineReuseBuffer(line, packet);
        return;
    }
    if (UNLIKELY(atomicLoad(&ls->ingress->closing)))
    {
        lineReuseBuffer(line, packet);
        closeOrphanIngress(t, line);
        return;
    }
    receive_t *received = memoryAllocate(sizeof(*received));
    *received           = (receive_t) {.ingress    = ls->ingress,
                                       .generation = state->connection ? authenticationclientUsersGeneration(state->auth) : 0};
    ingressRetain(ls->ingress);
    wireguardDispatch(&state->dispatch, 0, t, packet, received, receive, releaseReceive);
}
static void sendInner(tunnel_t *t, sbuf_t *packet, void *argument)
{
    const uint64_t epoch = *(const uint64_t *) argument;
    server_t      *state = tunnelGetState(t);
    if (state->releasing_since == NULL)
        reconcile(state, false);
    if (state->connection)
    {
        if (UNLIKELY(sbufGetLength(packet) < 20 || (sbufGetRawPtr(packet)[0] >> 4U) != 4))
            goto refuse;
        ip_addr_t  ip;
        ip4_addr_t address;
        memoryCopy(&address.addr, sbufGetRawPtr(packet) + 16, 4);
        ipAddrCopyFromIp4(ip, address);
        if (UNLIKELY(epoch == 0 || sourceEpoch(state, &ip) != epoch))
            goto refuse;
    }
    /* Reconciliation and authorization can take time after a packet leaves its slot. */
    if (state->releasing_since != NULL && wireguardExpired(*state->releasing_since, REKEY_ATTEMPT_TIME))
        goto refuse;
    wireguardCommonSendInner(&state->engine, packet);
    return;
refuse:
    sbufDestroy(packet);
}
static void freeArgument(void *argument)
{
    memoryFree(argument);
}
static void payloadDown(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    server_t *state = tunnelGetState(t);
    assert(tunnelchainIsWorkerPacketLine(t->chain, line));
    discard   line;
    uint64_t *epoch = memoryAllocate(sizeof(*epoch));
    *epoch          = 0;
    if (state->connection && sbufGetLength(packet) >= 20 && (sbufGetRawPtr(packet)[0] >> 4U) == 4)
    {
        ip_addr_t  ip;
        ip4_addr_t address;
        memoryCopy(&address.addr, sbufGetRawPtr(packet) + 16, 4);
        ipAddrCopyFromIp4(ip, address);
        *epoch = sourceEpoch(state, &ip);
    }
    wireguardDispatch(&state->dispatch, 0, t, packet, epoch, sendInner, freeArgument);
}

static void absorb(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}
static void detachIngress(tunnel_t *t, line_t *line)
{
    server_t      *state   = tunnelGetState(t);
    server_line_t *ls      = lineGetState(line, t);
    ingress_t     *ingress = ls->ingress;
    ls->ingress            = NULL;
    if (ingress == NULL)
        return;
    if (ingress->previous != NULL)
        ingress->previous->next = ingress->next;
    else
        state->ingress_heads[ingress->worker] = ingress->next;
    if (ingress->next != NULL)
        ingress->next->previous = ingress->previous;
    mutexLock(&state->bindings_lock);
    mutexLock(&ingress->lock);
    ingress->line = NULL;
    releaseIngressCharge(state, ingress);
    atomicSub(&state->ingress_count, 1);
    mutexUnlock(&ingress->lock);
    for (binding_t *binding = ingress->binding_head; binding != NULL; binding = binding->ingress_next)
        discardPending(binding);
    mutexUnlock(&state->bindings_lock);
    lineUnref(line);
    ingressRelease(ingress);
}
static void initUp(tunnel_t *t, line_t *line)
{
    server_t *state = tunnelGetState(t);
    assert(! tunnelchainIsWorkerPacketLine(t->chain, line));
    server_line_t *ls                    = lineGetState(line, t);
    *ls                                  = (server_line_t) {0};
    const address_context_t *source      = lineGetSourceAddressContext(line);
    address_context_t       *destination = lineGetDestinationAddressContext(line);
    /* UDP ingress keeps the remote port separately from its local listener port. */
    const uint16_t peer_port = lineGetRoutingContext(line)->peer_source_port;
    if (UNLIKELY(! atomicLoad(&state->dispatch.open) || ! addresscontextIsIpType(source) || peer_port == 0))
    {
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    if (addresscontextSelectTransport(destination, kAddressContextTransportUdp) == 0)
    {
        tunnelLogTransportRefusal(t, destination, kAddressContextTransportUdp);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    addresscontextSetOnlyProtocol(destination, IP_PROTO_UDP);
    if (! reserveFreshIngress(state))
    {
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    ingress_t *ingress = memoryAllocateZero(sizeof(*ingress));
    if (UNLIKELY(! mutexTryInit(&ingress->lock)))
    {
        memoryFree(ingress);
        mutexLock(&state->bindings_lock);
        --state->unauthenticated_ingress;
        mutexUnlock(&state->bindings_lock);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    atomic_init(&ingress->references, 1);
    atomic_init(&ingress->closing, false);
    atomicAdd(&state->ingress_count, 1);
    ingress->awaiting_proof = true;
    ingress->line           = line;
    ingress->worker         = lineGetWID(line);
    ingress->ip             = source->ip_address;
    ingress->port           = peer_port;
    lineRef(line);
    ls->ingress   = ingress;
    ingress->next = state->ingress_heads[ingress->worker];
    if (ingress->next != NULL)
        ingress->next->previous = ingress;
    state->ingress_heads[ingress->worker] = ingress;
    tunnelPrevDownStreamEst(t, line);
}
static void finishUp(tunnel_t *t, line_t *line)
{
    detachIngress(t, line);
}
static void finishDown(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    LOGF("WireGuardServer: unexpected Finish on inner packet line");
    abortProgramNow(1);
}
static void pauseUp(tunnel_t *t, line_t *line)
{
    server_line_t *ls = lineGetState(line, t);
    if (ls->ingress != NULL)
    {
        mutexLock(&ls->ingress->lock);
        ls->ingress->paused = true;
        mutexUnlock(&ls->ingress->lock);
    }
}
static void resumeUp(tunnel_t *t, line_t *line)
{
    server_line_t *ls = lineGetState(line, t);
    if (ls->ingress != NULL)
    {
        mutexLock(&ls->ingress->lock);
        ls->ingress->paused = false;
        mutexUnlock(&ls->ingress->lock);
    }
}

/* The binding helper borrows PTC's normal lines and never owns packet lines. */
static void bindingInit(tunnel_t *t, line_t *line)
{
    server_t                                      *state    = *(server_t **) tunnelGetState(t);
    const uint64_t                                 epoch    = ptcLineSourceEpoch(state->ptc, line);
    uint8_t                                        key[32]  = {0};
    authenticationclient_wireguard_authorization_t expected = {0}, current = {0};
    bool                                           found = false;
    mutexLock(&state->bindings_lock);
    const binding_t *binding = bindingByEpoch(state, epoch);
    if (bindingCurrent(binding))
    {
        memoryCopy(key, binding->public_key, sizeof(key));
        expected.handle     = binding->authorization.handle;
        expected.network    = binding->authorization.network;
        expected.mask       = binding->authorization.mask;
        expected.continuity = binding->authorization.continuity;
        found               = true;
    }
    mutexUnlock(&state->bindings_lock);
    const bool accepted = found &&
                          authenticationclientCopyWireGuardAuthorization(state->auth, key, &current) ==
                              kAuthenticationClientUserLookupOk &&
                          sameAuthorization(&current, &expected) &&
                          current.generation == authenticationclientUsersGeneration(state->auth) &&
                          sourceEpoch(state, &lineGetSourceAddressContext(line)->ip_address) == epoch;
    wCryptoZero(key, sizeof(key));
    if (! accepted)
    {
        authenticationclientWireGuardAuthorizationClear(&current);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    lineAddUser(line, &current.handle, current.profile.name, current.profile.password);
    authenticationclientWireGuardAuthorizationClear(&current);
    tunnelNextUpStreamInit(t, line);
}
static usercontroller_payload_mode_t payloadMode(tunnel_t *owner, line_t *line)
{
    server_t *state = tunnelGetState(owner);
    return ptcLineIsDatagram(state->ptc, line) ? kUserControllerPayloadDatagram : kUserControllerPayloadStream;
}
static void chain(tunnel_t *t, tunnel_chain_t *chain)
{
    server_t *state = tunnelGetState(t);
    if (! state->connection)
    {
        tunnelDefaultOnChain(t, chain);
        return;
    }
    tunnelchainInsert(chain, t);
    tunnelchainInsert(chain, state->ptc);
    tunnelchainInsert(chain, state->binder);
    if (startupFailurePending())
        return;
    tunnelBind(t, state->ptc);
    tunnelBind(state->ptc, state->binder);
    tunnelBind(state->binder, state->controller);
    state->controller->onChain(state->controller, chain);
}
static void prepare(tunnel_t *t)
{
    server_t *state      = tunnelGetState(t);
    state->ingress_heads = memoryAllocateZero(sizeof(*state->ingress_heads) * t->chain->workers_count);
    if (state->connection)
    {
        state->auth = state->auth_node->instance;
        if (state->auth == NULL)
        {
            LOGF("WireGuardServer: AuthenticationClient service is unavailable");
            startupFailureRecord(1);
        }
    }
}
static void tick(wtimer_t *timer)
{
    server_t *state = weventGetUserdata(timer);
    if (! atomicLoad(&state->dispatch.open))
        return;
    retryOrphanCloses(state);
    reconcile(state, true);
    wireguardCommonLoop(&state->engine);
    servicePending(state);
}
static void packetInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard   arg2;
    discard   arg3;
    tunnel_t *t     = arg1;
    server_t *state = tunnelGetState(t);
    if (! atomicLoad(&state->dispatch.open))
        return;
    line_t *line = tunnelchainGetWorkerPacketLine(t->chain, ((worker_t *) worker)->wid);
    tunnelNextUpStreamInit(t, line);
}
static void start(tunnel_t *t)
{
    server_t *state = tunnelGetState(t);
    /* Each routed server initializes its own consumers on the shared worker packet lines. */
    for (wid_t wid = 0; wid < t->chain->workers_count; ++wid)
    {
        const worker_message_submit_result_e result =
            sendWorkerMessageForceQueueWithCleanup(wid, packetInit, NULL, t, NULL, NULL);
        if (result != kWorkerMessageSubmitAccepted)
        {
            startupFailureRecord(1);
            return;
        }
    }
    state->timer = wtimerAdd(getWorkerLoop(0), tick, WIREGUARDIF_TIMER_MSECS, INFINITE);
    if (state->timer == NULL)
    {
        startupFailureRecord(1);
        return;
    }
    weventSetUserData(state->timer, state);
}
static void quiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    atomicStore(&state->dispatch.open, false);
}
static void quiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    if (wid != 0)
        return;
    if (state->timer != NULL)
    {
        wtimerDelete(state->timer);
        state->timer = NULL;
    }
    mutexLock(&state->bindings_lock);
    for (binding_t *binding = state->binding_head; binding != NULL; binding = binding->next)
        discardPending(binding);
    mutexUnlock(&state->bindings_lock);
}
static void stopWorker(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    while (state->ingress_heads != NULL && state->ingress_heads[wid] != NULL)
    {
        line_t *line = state->ingress_heads[wid]->line;
        lineRef(line);
        detachIngress(t, line);
        tunnelPrevDownStreamFinish(t, line);
        lineUnref(line);
    }
}
static void destroyChild(node_t *node, tunnel_t *child)
{
    if (child != NULL)
        tunnelOwnedChildDestroy(child);
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
}
static void destroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    assert(atomicLoad(&state->dispatch.count) == 0 && atomicLoad(&state->ingress_count) == 0);
    destroyChild(&state->ptc_node, state->ptc);
    destroyChild(&state->binding_node, state->binder);
    destroyChild(&state->controller_node, state->controller);
    while (state->binding_head != NULL)
        clearBinding(state, state->binding_head);
    binding_map_t_drop(&state->epochs);
    wireguardPrefixDestroy(&state->ranges);
    memoryFree(state->ingress_heads);
    wireguardDeviceDestroy(&state->engine);
    mutexDestroy(&state->bindings_lock);
    tunnelDestroy(t);
}
static bool createPipeline(server_t *state, node_t *node)
{
    node_t binding_template    = {.type                  = stringDuplicate("WireGuardUserBinding"),
                                  .version               = 1,
                                  .layer_group           = kNodeLayer4,
                                  .layer_group_prev_node = kNodeLayer4,
                                  .layer_group_next_node = kNodeLayer4,
                                  .can_have_next         = true,
                                  .can_have_prev         = true};
    binding_template.hash_type = calcHashBytes(binding_template.type, strlen(binding_template.type));
    if (! nodeConfigureChild(&state->ptc_node,
                             nodePacketsToConnectionGet(),
                             node,
                             ".packets",
                             kNodeChildLinkNone,
                             node->node_settings_json) ||
        ! nodeConfigureChild(&state->binding_node, binding_template, node, ".binding", kNodeChildLinkNone, NULL) ||
        ! nodeConfigureChild(&state->controller_node,
                             nodeUserControllerGet(),
                             node,
                             ".users",
                             kNodeChildLinkOwnerNext,
                             node->node_settings_json))
    {
        if (state->binding_node.type != binding_template.type)
            memoryFree(binding_template.type);
        return false;
    }
    state->ptc = nodemanagerCreateTunnelInstance(&state->ptc_node);
    if (state->ptc == NULL)
        return false;
    state->ptc_node.instance = state->ptc;
    ptcSetSourceEpochProvider(state->ptc, state, sourceEpoch);
    state->binder = tunnelCreate(&state->binding_node, sizeof(server_t *), 0);
    if (state->binder == NULL)
        return false;
    state->binding_node.instance                 = state->binder;
    *(server_t **) tunnelGetState(state->binder) = state;
    state->binder->fnInitU                       = bindingInit;
    state->controller                            = nodemanagerCreateTunnelInstance(&state->controller_node);
    if (state->controller == NULL)
        return false;
    state->controller_node.instance = state->controller;
    usercontrollerSetPayloadModeResolver(state->controller, state->tunnel, payloadMode);
    return true;
}
static bool readServerLimits(server_t *state, const cJSON *settings)
{
    int64_t ingress = kDefaultMaxUnauthenticatedIngress;
    int64_t pending = kDefaultMaxPendingRekeyBytes;
    if (jsonGetObjectIntegerInRange(settings, "max-unauthenticated-ingress", 1, INT_MAX, &ingress) ==
            kJsonValueInvalid ||
        jsonGetObjectIntegerInRange(settings, "max-pending-rekey-bytes", 0, UINT32_MAX, &pending) == kJsonValueInvalid)
        return false;
    state->max_unauthenticated_ingress = (unsigned) ingress;
    state->max_pending_rekey_bytes     = (size_t) pending;
    return true;
}

static tunnel_t *create(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(server_t), sizeof(server_line_t));
    if (t == NULL)
        return NULL;
    server_t *state = tunnelGetState(t);
    state->tunnel   = t;
    atomic_init(&state->ingress_count, 0);
    wireguardDispatchInit(&state->dispatch);
    if (! mutexTryInit(&state->bindings_lock))
    {
        tunnelDestroy(t);
        return NULL;
    }
    const cJSON *settings = node->node_settings_json;
    const cJSON *mode     = cJSON_GetObjectItemCaseSensitive(settings, "mode");
    const cJSON *key      = cJSON_GetObjectItemCaseSensitive(settings, "privatekey");
    const cJSON *auth     = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");
    const cJSON *peers    = cJSON_GetObjectItemCaseSensitive(settings, "peers");
    if (! readServerLimits(state, settings) || ! jsonObjectFieldStringsAreExact(settings, "mode") ||
        ! jsonObjectFieldStringsAreExact(settings, "privatekey") ||
        ! jsonObjectFieldStringsAreExact(settings, "auth-client-node-name") || ! cJSON_IsString(mode) ||
        (strcmp(mode->valuestring, "packet") != 0 && strcmp(mode->valuestring, "connection") != 0) ||
        ! cJSON_IsString(key) || node->hash_next == 0)
        goto fail;
    state->connection = strcmp(mode->valuestring, "connection") == 0;
    if (! wireguardCommonInit(&state->engine,
                              key->valuestring,
                              state,
                              (wireguard_callbacks_t) {.output          = output,
                                                       .inner           = inner,
                                                       .can_initiate    = canInitiate,
                                                       .key_unavailable = keyUnavailable,
                                                       .authenticated   = authenticated,
                                                       .candidate       = state->connection ? candidate : NULL}))
        goto fail;
    if (state->connection)
    {
        if (! cJSON_IsString(auth) || auth->valuestring[0] == '\0' || peers != NULL ||
            cJSON_GetObjectItemCaseSensitive(settings, "presharedkey") != NULL)
            goto fail;
        state->auth_node = nodemanagerGetConfigNodeByName(node->node_manager_config, auth->valuestring);
        if (state->auth_node == NULL || strcmp(state->auth_node->type, "AuthenticationClient") != 0 ||
            ! createPipeline(state, node))
            goto fail;
    }
    else
    {
        if (auth != NULL || ! cJSON_IsArray(peers) || cJSON_GetArraySize(peers) < 1)
            goto fail;
        const cJSON *entry;
        cJSON_ArrayForEach(entry, peers)
        {
            size_t id;
            if (cJSON_GetObjectItemCaseSensitive(entry, "endpoint") != NULL ||
                ! wireguardCommonAddConfiguredPeer(&state->engine, entry, &id) ||
                createBinding(state, peerLookupByPeerIndex(&state->engine, id), NULL) == NULL)
                goto fail;
        }
    }
    t->fnInitU          = initUp;
    t->fnInitD          = absorb;
    t->fnEstU           = absorb;
    t->fnEstD           = absorb;
    t->fnPayloadU       = payloadUp;
    t->fnPayloadD       = payloadDown;
    t->fnFinU           = finishUp;
    t->fnFinD           = finishDown;
    t->fnPauseU         = pauseUp;
    t->fnResumeU        = resumeUp;
    t->fnPauseD         = absorb;
    t->fnResumeD        = absorb;
    t->onChain          = chain;
    t->onPrepare        = prepare;
    t->onStart          = start;
    t->onQuiesceRequest = quiesceRequest;
    t->onWorkerQuiesce  = quiesce;
    t->onWorkerStop     = stopWorker;
    t->onDestroy        = destroy;
    return t;
fail:
    LOGF("WireGuardServer: invalid mode, key, peer ranges, or authentication configuration");
    destroy(t, wwLifecycleStartupRollback());
    return NULL;
}
node_t nodeWireGuardServerGet(void)
{
    const char *type = "WireGuardServer";
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, strlen(type)),
                     .version               = 1,
                     .createHandle          = create,
                     .required_padding_left = 16,
                     .layer_group           = kNodeLayer3 | kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4Datagram,
                     .layer_group_next_node = kNodeLayer3,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
