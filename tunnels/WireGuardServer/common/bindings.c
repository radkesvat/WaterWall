#include "PacketsToConnection/interface.h"
#include "WireGuardServer/structure.h"
#include "loggers/network_logger.h"

/* Access under bindings_lock on foreign workers. Never retain the result across an unlock there. */
binding_t *wireguardserverBindingByEpoch(server_t *state, uint64_t epoch)
{
    const binding_map_t_value *entry = binding_map_t_get(&state->epochs, epoch);
    return entry == NULL ? NULL : entry->second;
}

bool wireguardserverBindingCurrent(const binding_t *binding)
{
    return binding != NULL && binding->usable && ! binding->retiring;
}

uint64_t wireguardserverSourceEpoch(void *context, const ip_addr_t *source)
{
    server_t *state = context;
    if (UNLIKELY(! atomicLoad(&state->dispatch.open)) || ! IP_IS_V4(source))
        return 0;
    uint8_t                                        key[32];
    authenticationclient_wireguard_authorization_t expected = {0};
    mutexLock(&state->bindings_lock);
    const binding_t *binding = wireguardPrefixLookup(&state->ranges, source);
    if (! wireguardserverBindingCurrent(binding))
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
    const bool live = wireguardserverBindingCurrent(wireguardserverBindingByEpoch(state, epoch));
    mutexUnlock(&state->bindings_lock);
    return live ? epoch : 0;
}

/* The range owner must stay unique even if the engine reuses a retired peer's ID. */
static size_t rangeOwner(const binding_t *binding)
{
    return (size_t) (uintptr_t) binding;
}

binding_t *wireguardserverCreateBinding(server_t *state, wireguard_peer_t *peer,
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

void wireguardserverClearBinding(server_t *state, binding_t *binding)
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
    wireguardserverDiscardPending(binding);
    wireguardserverSetBindingIngress(binding, NULL);
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
        wireguardserverClearBinding(binding->server, binding);
    }
}

void wireguardserverRetireBinding(server_t *state, binding_t *binding)
{
    if (binding->retiring)
        return;
    if (! binding->usable)
    {
        wireguardserverClearBinding(state, binding);
        return;
    }
    mutexLock(&state->bindings_lock);
    binding->usable   = false;
    binding->retiring = true;
    wireguardserverDiscardPending(binding);
    wireguardserverSetBindingIngress(binding, NULL);
    mutexUnlock(&state->bindings_lock);
    discard wireguardifRemovePeer(&state->engine, binding->peer->id);
    binding->peer = NULL;
    ptcRetireSourceRange(
        state->ptc, &binding->authorization.network, &binding->authorization.mask, 0, retired, binding);
}
