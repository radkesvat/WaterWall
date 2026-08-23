#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodePingClientGet(void)
{
    const char *type_name       = "PingClient";
    node_t      node_pingclient = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0002,
             .createHandle          = pingclientCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagNone,
             .required_padding_left = kPingClientEncapsulationOverhead,
             .layer_group           = kNodeLayer3,
             .layer_group_next_node = kNodeLayer3,
             .layer_group_prev_node = kNodeLayer3,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_pingclient;
}
