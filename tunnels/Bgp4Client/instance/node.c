#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeBgp4ClientGet(void)
{
    const char *type_name = "Bgp4Client";
    node_t      node      = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = bgp4clientTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagNone,
             .required_padding_left = kBgp4ClientRequiredPaddingLeft,
             .layer_group           = kNodeLayer4,
             .layer_group_next_node = kNodeLayer4,
             .layer_group_prev_node = kNodeLayer4,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node;
}
