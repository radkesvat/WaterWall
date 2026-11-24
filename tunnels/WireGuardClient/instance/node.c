#include "WireGuardClient/interface.h"

node_t nodeWireGuardClientGet(void)
{
    const char *type = "WireGuardClient";
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, strlen(type)),
                     .version               = 1,
                     .createHandle          = wireguardclientTunnelCreate,
                     .required_padding_left = 16,
                     .layer_group           = kNodeLayer3 | kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer3,
                     .layer_group_next_node = kNodeLayer4Datagram,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
