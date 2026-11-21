#include "RtmpServer/interface.h"

node_t nodeRtmpServerGet(void)
{
    const char *type = "RtmpServer";
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, stringLength(type)),
                     .version               = 1,
                     .createHandle          = rtmpserverTunnelCreate,
                     .flags                 = kNodeFlagBlocksSplice,
                     .required_padding_left = 0,
                     .layer_group           = kNodeLayer4,
                     .layer_group_next_node = kNodeLayer4Stream,
                     .layer_group_prev_node = kNodeLayer4Stream,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
