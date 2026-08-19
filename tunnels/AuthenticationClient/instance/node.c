#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeAuthenticationClientGet(void)
{
    const char *type_name                 = "AuthenticationClient";
    node_t      node_authenticationclient = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = authenticationclientTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagChainHead,
             .required_padding_left = 0,
             .layer_group           = kNodeLayer4,
             .layer_group_next_node = kNodeLayer4,
             .layer_group_prev_node = kNodeLayerNone,
             .can_have_next         = true,
             .can_have_prev         = false,
    };
    return node_authenticationclient;
}
