#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodePacketCounterGet(void)
{
    const char *type_name          = "PacketCounter";
    node_t      node_packetcounter = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = packetcounterTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagChainHead | kNodeFlagChainEnd,
             .required_padding_left = 0,
             .layer_group           = kNodeLayer3,
             .layer_group_next_node = kNodeLayer3,
             .layer_group_prev_node = kNodeLayer3,
             .can_have_next         = true,
             .can_have_prev         = true,
             .is_adapter            = true,
    };
    return node_packetcounter;
}
