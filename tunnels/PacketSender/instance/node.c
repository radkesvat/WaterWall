#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodePacketSenderGet(void)
{
    const char *type_name         = "PacketSender";
    node_t      node_packetsender = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = packetsenderTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagChainHead | kNodeFlagSingleton,
             .required_padding_left = 0,
             .layer_group           = kNodeLayer3,
             .layer_group_next_node = kNodeLayer3,
             .layer_group_prev_node = kNodeLayerAnything,
             .can_have_next         = true,
             .can_have_prev         = false,
             .is_adapter            = true,
    };
    return node_packetsender;
}

