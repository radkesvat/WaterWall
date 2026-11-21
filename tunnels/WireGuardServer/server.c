#include "AuthenticationClient/interface.h"
#include "PacketsToConnection/interface.h"
#include "UserController/interface.h"
#include "WireGuardCommon/dispatch.h"
#include "WireGuardCommon/engine.h"
#include "WireGuardServer/interface.h"
#include "loggers/network_logger.h"

typedef struct ingress_s ingress_t;
typedef struct server_s  server_t;
typedef struct binding_s
{
    server_t                                      *server;
    authenticationclient_wireguard_authorization_t authorization;
    ingress_t                                     *ingress;
    uint64_t                                       epoch;
    uint8_t                                        public_key[32];
    bool                                           occupied, usable, retiring;
    atomic_bool                                    retirement_done, retirement_ok;
} binding_t;

struct ingress_s
{
    atomic_uint references;
    wmutex_t    lock;
    line_t     *line;            /* Borrowed normal, created by the UDP ingress adapter. */
    ingress_t  *next, *previous; /* Owner-worker inventory. */
    ip_addr_t   ip;
    uint16_t    port;
    wid_t       worker;
    bool        paused;
};
typedef struct server_line_s
{
    ingress_t *ingress;
} server_line_t;
struct server_s
{
    wireguard_device_t   engine;
    wireguard_dispatch_t dispatch;
    tunnel_t            *tunnel;
    wmutex_t             bindings_lock;
    binding_t            bindings[WIREGUARD_MAX_PEERS];
    ingress_t          **ingress_heads;
    atomic_uint          ingress_count;
    ingress_t           *receiving;
    wtimer_t            *timer;
    uint64_t             next_epoch, reconciled_generation, receiving_generation;
    bool                 connection;
    node_t              *auth_node;
    tunnel_t            *auth;
    node_t               ptc_node, binding_node, controller_node;
    tunnel_t            *ptc, *binder, *controller;
};

typedef struct send_s
{
    ingress_t *ingress;
    uint64_t   epoch;
    uint8_t    peer;
    bool       peer_bound;
} send_t;

static void ingressRetain(ingress_t *ingress)
{
    atomicAdd(&ingress->references, 1);
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
static bool bindingCurrent(server_t *state, const binding_t *binding)
{
    discard state;
    return binding->usable && ! binding->retiring;
}
static uint64_t sourceEpoch(void *context, const ip_addr_t *source)
{
    server_t                                      *state          = context;
    uint64_t                                       epoch          = 0;
    unsigned                                       index          = 0;
    uint8_t                                        public_key[32] = {0};
    authenticationclient_wireguard_authorization_t expected       = {0};
    if (UNLIKELY(! atomicLoad(&state->dispatch.open)))
        return 0;
    mutexLock(&state->bindings_lock);
    for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
    {
        binding_t *binding = &state->bindings[i];
        if (binding->usable && ! binding->retiring && IP_IS_V4(source) &&
            ip4AddrNetcmp(
                ip_2_ip4(source), ip_2_ip4(&binding->authorization.network), ip_2_ip4(&binding->authorization.mask)))
        {
            epoch               = binding->epoch;
            index               = i;
            expected.handle     = binding->authorization.handle;
            expected.network    = binding->authorization.network;
            expected.mask       = binding->authorization.mask;
            expected.continuity = binding->authorization.continuity;
            memoryCopy(public_key, binding->public_key, sizeof(public_key));
            break;
        }
    }
    mutexUnlock(&state->bindings_lock);
    /* No binding or protocol mutex is held during the protected account read.
     * A continuous refresh keeps the epoch; credential changes close the gate
     * immediately, before the asynchronous owner-worker retirement begins. */
    if (epoch == 0 ||
        ! authenticationclientWireGuardAuthorizationMatches(
            state->auth, public_key, &expected.handle, expected.continuity, &expected.network, &expected.mask))
        return 0;
    mutexLock(&state->bindings_lock);
    const binding_t *binding = &state->bindings[index];
    const bool       live    = binding->usable && ! binding->retiring && binding->epoch == epoch;
    mutexUnlock(&state->bindings_lock);
    return live ? epoch : 0;
}
static void retired(void *context, bool success)
{
    /* Cancellation can arrive on a foreign teardown thread. Notification only. */
    binding_t *binding = context;
    atomicStore(&binding->retirement_ok, success);
    atomicStore(&binding->retirement_done, true);
}
static void clearBinding(server_t *state, unsigned index)
{
    binding_t                                     *binding = &state->bindings[index];
    ingress_t                                     *ingress;
    authenticationclient_wireguard_authorization_t old;
    mutexLock(&state->bindings_lock);
    ingress                = binding->ingress;
    old                    = binding->authorization;
    binding->ingress       = NULL;
    binding->authorization = (authenticationclient_wireguard_authorization_t) {0};
    binding->occupied = binding->usable = binding->retiring = false;
    wCryptoZero(binding->public_key, sizeof(binding->public_key));
    mutexUnlock(&state->bindings_lock);
    ingressRelease(ingress);
    authenticationclientWireGuardAuthorizationClear(&old);
    discard wireguardifRemovePeer(&state->engine, (uint8_t) index);
}
static void retireBinding(server_t *state, unsigned index)
{
    binding_t *binding = &state->bindings[index];
    if (! binding->occupied || binding->retiring)
        return;
    mutexLock(&state->bindings_lock);
    const bool had_flows = binding->usable;
    binding->usable      = false;
    binding->retiring    = true;
    mutexUnlock(&state->bindings_lock);
    /* No engine processing is concurrent with the single protocol owner. */
    discard wireguardifRemovePeer(&state->engine, (uint8_t) index);
    if (state->connection && had_flows)
    {
        atomicStore(&binding->retirement_done, false);
        atomicStore(&binding->retirement_ok, false);
        ptcRetireSourceRange(
            state->ptc, &binding->authorization.network, &binding->authorization.mask, 0, retired, binding);
    }
    else
        clearBinding(state, index);
}
static void reconcile(server_t *state)
{
    if (! state->connection)
        return;
    const uint64_t generation = authenticationclientUsersGeneration(state->auth);
    for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
    {
        binding_t *binding = &state->bindings[i];
        if (binding->retiring)
        {
            if (atomicLoad(&binding->retirement_done) && atomicLoad(&binding->retirement_ok))
                clearBinding(state, i);
            continue;
        }
        if (! binding->occupied || binding->authorization.generation == generation)
            continue;
        /* A table refresh revalidates the original identity through the cached
         * continuation policy. Explicit control rejection only blocks admission. */
        if (! binding->usable || ! authenticationclientWireGuardAuthorizationMatches(state->auth,
                                                                                     binding->public_key,
                                                                                     &binding->authorization.handle,
                                                                                     binding->authorization.continuity,
                                                                                     &binding->authorization.network,
                                                                                     &binding->authorization.mask))
            retireBinding(state, i);
        else
            binding->authorization.generation = generation;
    }
    state->reconciled_generation = generation;
}

static wireguard_peer_t *candidate(void *context, const uint8_t public_key[32])
{
    server_t                                      *state         = context;
    authenticationclient_wireguard_authorization_t authorization = {0};
    wireguard_peer_t                              *peer = peerLookupByPubkey(&state->engine, (uint8_t *) public_key);
    if (peer != NULL)
    {
        const unsigned index   = wireguardPeerIndex(&state->engine, peer);
        binding_t     *binding = &state->bindings[index];
        if (binding->authorization.continuity > state->receiving_generation)
            return NULL;
        /* Only a proved, live binding qualifies for continuation, including
         * rekey after all previous crypto keys have expired. */
        if (binding->usable && ! binding->retiring &&
            authenticationclientWireGuardAuthorizationMatches(state->auth,
                                                              binding->public_key,
                                                              &binding->authorization.handle,
                                                              binding->authorization.continuity,
                                                              &binding->authorization.network,
                                                              &binding->authorization.mask))
            return peer;
        retireBinding(state, index);
        return NULL;
    }
    /* The intake generation rejects a proof queued before this credential/range
     * incarnation, while continuous full-table refreshes remain admissible. */
    if (authenticationclientCopyWireGuardAuthorization(state->auth, public_key, &authorization) !=
            kAuthenticationClientUserLookupOk ||
        ! IP_IS_V4(&authorization.network) || authorization.continuity > state->receiving_generation)
        goto reject;
    /* Retiring ranges remain reserved until all owner workers acknowledge. */
    wireguard_allowed_ip_t requested = {.valid = true, .ip = authorization.network, .mask = authorization.mask};
    for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
    {
        binding_t *binding = &state->bindings[i];
        if (! binding->occupied)
            continue;
        wireguard_allowed_ip_t existing = {
            .valid = true, .ip = binding->authorization.network, .mask = binding->authorization.mask};
        if (wireguardCommonRangesOverlap(&requested, &existing))
            goto reject;
    }
    unsigned index;
    for (index = 0; index < WIREGUARD_MAX_PEERS; ++index)
        if (! state->bindings[index].occupied)
            break;
    if (index == WIREGUARD_MAX_PEERS || authorization.generation != authenticationclientUsersGeneration(state->auth))
        goto reject;
    peer = &state->engine.peers[index];
    if (! wireguardPeerInit(&state->engine, peer, public_key, NULL))
        goto reject;
    peer->allowed_source_ips[0] = requested;
    binding_t *binding          = &state->bindings[index];
    if (UNLIKELY(state->next_epoch == UINT64_MAX))
    {
        LOGF("WireGuardServer: binding epoch exhausted");
        abortProgramNow(1);
    }
    mutexLock(&state->bindings_lock);
    binding->authorization = authorization;
    memoryCopy(binding->public_key, public_key, 32);
    binding->occupied = true;
    binding->epoch    = ++state->next_epoch;
    mutexUnlock(&state->bindings_lock);
    return peer;
reject:
    authenticationclientWireGuardAuthorizationClear(&authorization);
    return NULL;
}

static bool authenticated(void *context, wireguard_peer_t *peer)
{
    server_t      *state   = context;
    const unsigned index   = wireguardPeerIndex(&state->engine, peer);
    binding_t     *binding = &state->bindings[index];
    if (UNLIKELY(state->connection && binding->authorization.continuity > state->receiving_generation))
        return false;
    if (state->connection)
    {
        bool valid;
        if (binding->usable && ! binding->retiring)
            valid = binding->authorization.continuity <= state->receiving_generation &&
                    authenticationclientWireGuardAuthorizationMatches(state->auth,
                                                                      binding->public_key,
                                                                      &binding->authorization.handle,
                                                                      binding->authorization.continuity,
                                                                      &binding->authorization.network,
                                                                      &binding->authorization.mask);
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
            retireBinding(state, index);
            return false;
        }
    }
    if (UNLIKELY(binding->retiring || state->receiving == NULL))
        return false;
    ingressRetain(state->receiving);
    mutexLock(&state->bindings_lock);
    ingress_t *old   = binding->ingress;
    binding->ingress = state->receiving;
    binding->usable  = true;
    mutexUnlock(&state->bindings_lock);
    ingressRelease(old);
    return true;
}

static void sendOnIngress(tunnel_t *t, sbuf_t *packet, void *argument)
{
    server_t *state = tunnelGetState(t);
    send_t   *send  = argument;
    if (send->peer_bound)
    {
        authenticationclient_wireguard_authorization_t expected = {0};
        uint8_t                                        key[32]  = {0};
        mutexLock(&state->bindings_lock);
        const binding_t *binding = &state->bindings[send->peer];
        bool             valid   = bindingCurrent(state, binding) && binding->epoch == send->epoch;
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
        valid = valid && bindingCurrent(state, binding) && binding->epoch == send->epoch;
        mutexUnlock(&state->bindings_lock);
        if (UNLIKELY(! valid))
        {
            reuseBuffer(packet);
            return;
        }
    }
    ingress_t *ingress = send->ingress;
    mutexLock(&ingress->lock);
    line_t    *line     = ingress->line;
    const bool writable = line != NULL && ! ingress->paused;
    if (writable)
        lineRef(line);
    mutexUnlock(&ingress->lock);
    if (! writable)
    {
        reuseBuffer(packet);
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
    for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
    {
        wireguard_peer_t *peer    = &state->engine.peers[i];
        binding_t        *binding = &state->bindings[i];
        if (peer == selected_peer && peer->valid && binding->usable && ipAddrCmp(&peer->ip, ip) && peer->port == port &&
            binding->ingress != NULL)
        {
            ingress             = binding->ingress;
            snapshot.peer       = (uint8_t) i;
            snapshot.epoch      = binding->epoch;
            snapshot.peer_bound = true;
            break;
        }
    }
    if (ingress == NULL && state->receiving != NULL && ipAddrCmp(&state->receiving->ip, ip) &&
        state->receiving->port == port)
        ingress = state->receiving;
    if (ingress == NULL)
    {
        reuseBuffer(packet);
        return false;
    }
    send_t *send  = memoryAllocate(sizeof(*send));
    *send         = snapshot;
    send->ingress = ingress;
    ingressRetain(ingress);
    wireguardDispatch(&state->dispatch, ingress->worker, state->tunnel, packet, send, sendOnIngress, releaseSend);
    return true;
}
static void inner(void *context, sbuf_t *packet, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = &state->bindings[wireguardPeerIndex(&state->engine, peer)];
    if (UNLIKELY(! bindingCurrent(state, binding)))
    {
        reuseBuffer(packet);
        return;
    }
    line_t *line = tunnelchainGetWorkerPacketLine(state->tunnel->chain, 0);
    tunnelNextUpStreamPayload(state->tunnel, line, packet);
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
    reconcile(state);
    mutexLock(&ingress->lock);
    bool live = ingress->line != NULL;
    mutexUnlock(&ingress->lock);
    if (UNLIKELY(! live))
    {
        reuseBuffer(packet);
        return;
    }
    state->receiving            = ingress;
    state->receiving_generation = received->generation;
    wireguardCommonReceive(&state->engine, packet, &ingress->ip, ingress->port);
    state->receiving            = NULL;
    state->receiving_generation = 0;
    /* Failed candidate proofs never retain a peer slot or range reservation. */
    if (state->connection)
        for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
            if (state->bindings[i].occupied && ! state->bindings[i].usable && ! state->bindings[i].retiring)
                clearBinding(state, i);
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
    receive_t *received = memoryAllocate(sizeof(*received));
    *received           = (receive_t) {.ingress    = ls->ingress,
                                       .generation = state->connection ? authenticationclientUsersGeneration(state->auth) : 0};
    ingressRetain(ls->ingress);
    wireguardDispatch(&state->dispatch, 0, t, packet, received, receive, releaseReceive);
}
static void sendInner(tunnel_t *t, sbuf_t *packet, void *argument)
{
    const uint64_t epoch = *(uint64_t *) argument;
    server_t      *state = tunnelGetState(t);
    reconcile(state);
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
    wireguardCommonSendInner(&state->engine, packet);
    return;
refuse:
    reuseBuffer(packet);
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
    mutexLock(&ingress->lock);
    ingress->line = NULL;
    atomicSub(&state->ingress_count, 1);
    mutexUnlock(&ingress->lock);
    lineUnref(line);
    ingressRelease(ingress);
}
static void initUp(tunnel_t *t, line_t *line)
{
    server_t *state = tunnelGetState(t);
    assert(! tunnelchainIsWorkerPacketLine(t->chain, line));
    server_line_t *ls               = lineGetState(line, t);
    *ls                             = (server_line_t) {0};
    const address_context_t *source = lineGetSourceAddressContext(line);
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
    if (atomicAdd(&state->ingress_count, 1) >= 1024)
    {
        atomicSub(&state->ingress_count, 1);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    ingress_t *ingress = memoryAllocateZero(sizeof(*ingress));
    if (UNLIKELY(! mutexTryInit(&ingress->lock)))
    {
        memoryFree(ingress);
        atomicSub(&state->ingress_count, 1);
        tunnelPrevDownStreamFinish(t, line);
        return;
    }
    atomic_init(&ingress->references, 1);
    ingress->line   = line;
    ingress->worker = lineGetWID(line);
    ingress->ip     = source->ip_address;
    ingress->port   = peer_port;
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
    for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
    {
        binding_t *binding = &state->bindings[i];
        if (epoch != 0 && binding->usable && ! binding->retiring && binding->epoch == epoch)
        {
            memoryCopy(key, binding->public_key, sizeof(key));
            expected.handle     = binding->authorization.handle;
            expected.network    = binding->authorization.network;
            expected.mask       = binding->authorization.mask;
            expected.continuity = binding->authorization.continuity;
            found               = true;
            break;
        }
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
    reconcile(state);
    wireguardCommonLoop(&state->engine);
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
    if (! t->chain->packet_chain_init_sent)
    {
        for (unsigned i = 0; i < t->chain->workers_count; ++i)
        {
            const worker_message_submit_result_e result =
                sendWorkerMessageForceQueueWithCleanup((wid_t) i, packetInit, NULL, t, NULL, NULL);
            if (result != kWorkerMessageSubmitAccepted)
            {
                startupFailureRecord(1);
                return;
            }
        }
        t->chain->packet_chain_init_sent = true;
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
    if (wid == 0 && state->timer != NULL)
    {
        wtimerDelete(state->timer);
        state->timer = NULL;
    }
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
    for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
    {
        ingressRelease(state->bindings[i].ingress);
        authenticationclientWireGuardAuthorizationClear(&state->bindings[i].authorization);
    }
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
    for (unsigned i = 0; i < WIREGUARD_MAX_PEERS; ++i)
    {
        state->bindings[i].server = state;
        atomic_init(&state->bindings[i].retirement_done, false);
        atomic_init(&state->bindings[i].retirement_ok, false);
    }
    const cJSON *settings = node->node_settings_json;
    const cJSON *mode     = cJSON_GetObjectItemCaseSensitive(settings, "mode");
    const cJSON *key      = cJSON_GetObjectItemCaseSensitive(settings, "privatekey");
    const cJSON *auth     = cJSON_GetObjectItemCaseSensitive(settings, "auth-client-node-name");
    const cJSON *peers    = cJSON_GetObjectItemCaseSensitive(settings, "peers");
    if (! jsonObjectFieldStringsAreExact(settings, "mode") ||
        ! jsonObjectFieldStringsAreExact(settings, "privatekey") ||
        ! jsonObjectFieldStringsAreExact(settings, "auth-client-node-name") || ! cJSON_IsString(mode) ||
        (strcmp(mode->valuestring, "packet") != 0 && strcmp(mode->valuestring, "connection") != 0) ||
        ! cJSON_IsString(key) || node->hash_next == 0)
        goto fail;
    state->connection = strcmp(mode->valuestring, "connection") == 0;
    if (! wireguardCommonInit(&state->engine,
                              key->valuestring,
                              state,
                              (wireguard_callbacks_t) {.output        = output,
                                                       .inner         = inner,
                                                       .authenticated = authenticated,
                                                       .candidate     = state->connection ? candidate : NULL}))
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
        if (auth != NULL || ! cJSON_IsArray(peers) || cJSON_GetArraySize(peers) < 1 ||
            cJSON_GetArraySize(peers) > WIREGUARD_MAX_PEERS)
            goto fail;
        for (int i = 0; i < cJSON_GetArraySize(peers); ++i)
        {
            const cJSON *peer = cJSON_GetArrayItem(peers, i);
            uint8_t      index;
            if (cJSON_GetObjectItemCaseSensitive(peer, "endpoint") != NULL ||
                ! wireguardCommonAddConfiguredPeer(&state->engine, peer, &index))
                goto fail;
            for (int j = 0; j < i; ++j)
                for (unsigned a = 0; a < WIREGUARD_MAX_SRC_IPS; ++a)
                    for (unsigned b = 0; b < WIREGUARD_MAX_SRC_IPS; ++b)
                        if (wireguardCommonRangesOverlap(&state->engine.peers[index].allowed_source_ips[a],
                                                         &state->engine.peers[j].allowed_source_ips[b]))
                            goto fail;
            state->bindings[index].occupied = true;
            state->bindings[index].epoch    = ++state->next_epoch;
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
