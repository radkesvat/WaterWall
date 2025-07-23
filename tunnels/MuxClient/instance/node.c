#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeMuxClientGet(void)
{
    const char *type_name      = "MuxClient";
    node_t      node_muxclient = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = muxclientTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagNone,
             .required_padding_left = 8, // This is required for the mux_frame_t structure to be aligned correctly, see
                                    // kMuxFrameLength in structure.h
             .layer_group           = kNodeLayerAnything,
             .layer_group_next_node = kNodeLayerAnything,
             .layer_group_prev_node = kNodeLayerAnything,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_muxclient;
}
