#include "WireGuardServer/structure.h"

bool wireguardserverSameAuthorization(const authenticationclient_wireguard_authorization_t *a,
                                      const authenticationclient_wireguard_authorization_t *b)
{
    return a->handle.user_id == b->handle.user_id && a->continuity == b->continuity &&
           a->handle.generation >= b->handle.generation && ipAddrCmp(&a->network, &b->network) &&
           ipAddrCmp(&a->mask, &b->mask);
}

/* Owner-worker check, including cached eligibility while new admissions are closed. */
bool wireguardserverBindingAuthorized(server_t *state, const binding_t *binding)
{
    return authenticationclientWireGuardAuthorizationMatches(state->auth,
                                                             binding->public_key,
                                                             &binding->authorization.handle,
                                                             binding->authorization.continuity,
                                                             &binding->authorization.network,
                                                             &binding->authorization.mask);
}

void wireguardserverReconcile(server_t *state, bool periodic)
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
        if (! binding->usable || ! wireguardserverBindingAuthorized(state, binding))
            wireguardserverRetireBinding(state, binding);
        else
            binding->authorization.generation = generation;
    }
}

wireguard_peer_t *wireguardserverCandidate(void *context, const uint8_t public_key[32])
{
    server_t         *state = context;
    wireguard_peer_t *peer  = peerLookupByPubkey(&state->engine, public_key);
    if (peer != NULL)
    {
        binding_t *binding = peer->context;
        if (binding->authorization.continuity > state->receiving_generation)
            return NULL;
        if (wireguardserverBindingCurrent(binding) && wireguardserverBindingAuthorized(state, binding))
            return peer;
        wireguardserverRetireBinding(state, binding);
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
        state->provisional = wireguardserverCreateBinding(state, peer, &authorization);
        if (state->provisional != NULL)
            return peer;
    }
    discard wireguardifRemovePeer(&state->engine, peer->id);
reject:
    authenticationclientWireGuardAuthorizationClear(&authorization);
    return NULL;
}

bool wireguardserverAuthenticated(void *context, wireguard_peer_t *peer)
{
    server_t  *state   = context;
    binding_t *binding = peer->context;
    if (UNLIKELY(state->connection && binding->authorization.continuity > state->receiving_generation))
        return false;
    if (state->connection)
    {
        bool valid;
        if (binding->usable && ! binding->retiring)
            valid = binding->authorization.continuity <= state->receiving_generation &&
                    wireguardserverBindingAuthorized(state, binding);
        else
        {
            authenticationclient_wireguard_authorization_t authorization = {0};
            valid = authenticationclientCopyWireGuardAuthorization(state->auth, peer->public_key, &authorization) ==
                        kAuthenticationClientUserLookupOk &&
                    wireguardserverSameAuthorization(&authorization, &binding->authorization) &&
                    authorization.generation == authenticationclientUsersGeneration(state->auth);
            authenticationclientWireGuardAuthorizationClear(&authorization);
        }
        if (UNLIKELY(! valid))
        {
            wireguardserverRetireBinding(state, binding);
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
    wireguardserverSetBindingIngress(binding, state->receiving);
    binding->usable = true;
    mutexUnlock(&state->bindings_lock);
    state->received_binding = binding;
    if (state->provisional == binding)
        state->provisional = NULL;
    return true;
}
