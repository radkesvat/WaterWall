#include "WireGuardServer/interface.h"

node_t nodeWireGuardServerGet(void)
{
    const char *type = "WireGuardServer";
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, strlen(type)),
                     .version               = 1,
                     .createHandle          = wireguardserverTunnelCreate,
                     .required_padding_left = 16,
                     .layer_group           = kNodeLayer3 | kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4Datagram,
                     .layer_group_next_node = kNodeLayer3,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
