#include "interface.h"
#include "structure.h"

#include "loggers/network_logger.h"

node_t nodeSocks5ServerGet(void)
{
    const char *type_name         = "Socks5Server";
    node_t      node_socks5server = {
             .name                  = NULL,
             .type                  = stringDuplicate(type_name),
             .next                  = NULL,
             .hash_name             = 0,
             .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
             .hash_next             = 0,
             .version               = 0001,
             .createHandle          = socks5serverTunnelCreate,
             .node_json             = NULL,
             .node_settings_json    = NULL,
             .node_manager_config   = NULL,
             .instance              = NULL,
             .flags                 = kNodeFlagNone,
             .required_padding_left = kSocks5ServerUdpHeaderMaxLen,
             .layer_group           = kNodeLayer4,
             .layer_group_next_node = kNodeLayer4,
             .layer_group_prev_node = kNodeLayer4,
             .can_have_next         = true,
             .can_have_prev         = true,
    };
    return node_socks5server;
}
