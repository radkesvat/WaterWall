#include "PacketsToConnection/interface.h"
#include "WireGuardServer/structure.h"

bool wireguardserverCreatePipeline(server_t *state, node_t *node)
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
    ptcSetSourceEpochProvider(state->ptc, state, wireguardserverSourceEpoch);
    state->binder = tunnelCreate(&state->binding_node, sizeof(server_t *), 0);
    if (state->binder == NULL)
        return false;
    state->binding_node.instance                 = state->binder;
    *(server_t **) tunnelGetState(state->binder) = state;
    state->binder->fnInitU                       = wireguardserverBindingInit;
    state->controller                            = nodemanagerCreateTunnelInstance(&state->controller_node);
    if (state->controller == NULL)
        return false;
    state->controller_node.instance = state->controller;
    usercontrollerSetPayloadModeResolver(state->controller, state->tunnel, wireguardserverPayloadMode);
    return true;
}

void wireguardserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
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
