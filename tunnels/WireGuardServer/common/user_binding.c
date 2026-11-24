#include "PacketsToConnection/interface.h"
#include "WireGuardServer/structure.h"

/* The binding helper borrows PTC's normal lines and never owns packet lines. */
void wireguardserverBindingInit(tunnel_t *t, line_t *line)
{
    server_t                                      *state    = *(server_t **) tunnelGetState(t);
    const uint64_t                                 epoch    = ptcLineSourceEpoch(state->ptc, line);
    uint8_t                                        key[32]  = {0};
    authenticationclient_wireguard_authorization_t expected = {0}, current = {0};
    bool                                           found = false;
    mutexLock(&state->bindings_lock);
    const binding_t *binding = wireguardserverBindingByEpoch(state, epoch);
    if (wireguardserverBindingCurrent(binding))
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
                          wireguardserverSameAuthorization(&current, &expected) &&
                          current.generation == authenticationclientUsersGeneration(state->auth) &&
                          wireguardserverSourceEpoch(state, &lineGetSourceAddressContext(line)->ip_address) == epoch;
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

usercontroller_payload_mode_t wireguardserverPayloadMode(tunnel_t *owner, line_t *line)
{
    server_t *state = tunnelGetState(owner);
    return ptcLineIsDatagram(state->ptc, line) ? kUserControllerPayloadDatagram : kUserControllerPayloadStream;
}
