#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeRawSocketGet(void)
{
    const char *type_name      = "RawSocket";
    node_t      node_rawsocket = {
             .type                  = stringDuplicate(type_name),
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .version               = 0001,
             .createHandle          = rawsocketCreate,
             .destroyHandle         = rawsocketDestroy,
             .apiHandle             = rawsocketApi,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagChainEnd,
             .required_padding_left = 0,
             .layer_group           = kNodeLayer3,
             .layer_group_next_node = kNodeLayerAnything,
             .layer_group_prev_node = kNodeLayerAnything,
             .can_have_next         = true,
             .can_have_prev         = true,
             .is_adapter            = true,
    };
    return node_rawsocket;
}
