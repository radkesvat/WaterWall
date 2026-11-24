#include "WireGuardServer/structure.h"

static void destroyChild(node_t *node, tunnel_t *child)
{
    if (child != NULL)
        tunnelOwnedChildDestroy(child);
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
}

void wireguardserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard   context;
    server_t *state = tunnelGetState(t);
    assert(atomicLoad(&state->dispatch.count) == 0 && atomicLoad(&state->ingress_count) == 0);
    destroyChild(&state->ptc_node, state->ptc);
    destroyChild(&state->binding_node, state->binder);
    destroyChild(&state->controller_node, state->controller);
    while (state->binding_head != NULL)
        wireguardserverClearBinding(state, state->binding_head);
    binding_map_t_drop(&state->epochs);
    wireguardPrefixDestroy(&state->ranges);
    memoryFree(state->ingress_heads);
    wireguardDeviceDestroy(&state->engine);
    mutexDestroy(&state->bindings_lock);
    tunnelDestroy(t);
}
