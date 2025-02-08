#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeWireGuardDeviceGet(void)
{
    const char *type_name     = "WireGuardDevice";
    node_t      node_wireguarddevice = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = wireguarddeviceTunnelCreate,
             .destroyHandle         = wireguarddeviceTunnelDestroy,
             .apiHandle             = wireguarddeviceTunnelApi,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagNone,
             .required_padding_left = WIREGUARD_AUTHTAG_LEN,
             .layer_group           = kNodeLayer3,
             .layer_group_next_node = kNodeLayer3,
             .layer_group_prev_node = kNodeLayer3,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_wireguarddevice;
}
