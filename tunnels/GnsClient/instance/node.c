#include "GnsClient/interface.h"

node_t nodeGnsClientGet(void)
{
    const char *type = "GnsClient";
    /* No left padding is reserved: every buffer this node sends is built here. */
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, stringLength(type)),
                     .version               = 1,
                     .createHandle          = gnsclientTunnelCreate,
                     .flags                 = kNodeFlagBlocksSplice,
                     .required_padding_left = 0,
                     .layer_group           = kNodeLayer4,
                     .layer_group_next_node = kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
