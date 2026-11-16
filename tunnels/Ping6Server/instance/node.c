#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodePing6ServerGet(void)
{
    const char *type_name        = "Ping6Server";
    node_t      node_ping6server = {
        .name                  = NULL,
        .type                  = stringDuplicate(type_name),
        .next                  = NULL,
        .hash_name             = 0,
        .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
        .hash_next             = 0,
        .version               = 0001,
        .createHandle          = ping6serverCreate,
        .node_json             = NULL,
        .node_settings_json    = NULL,
        .node_manager_config   = NULL,
        .instance              = NULL,
        .flags                 = kNodeFlagNone,
        .required_padding_left = kPing6ServerEncapsulationOverhead,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
    return node_ping6server;
}
