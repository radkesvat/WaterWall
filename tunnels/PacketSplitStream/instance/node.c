#include "interface.h"
#include "structure.h"

node_t nodePacketSplitStreamGet(void)
{
    const char *type_name = "PacketSplitStream";
    node_t      node_packetsplitstream = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = packetsplitstreamTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagChainEnd,
             .required_padding_left = 0,
             .layer_group           = kNodeLayer3,
             .layer_group_next_node = kNodeLayerNone,
             .layer_group_prev_node = kNodeLayer3,
             .can_have_next         = false,
             .can_have_prev         = true,
    };
    return node_packetsplitstream;
}
