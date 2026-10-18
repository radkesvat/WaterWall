#include "APIServer/interface.h"

node_t nodeAPIServerGet(void)
{
    const char *name = "APIServer";
    return (node_t) {.type                  = stringDuplicate(name),
                     .hash_type             = calcHashBytes(name, stringLength(name)),
                     .version               = 1,
                     .createHandle          = apiserverTunnelCreate,
                     .flags                 = kNodeFlagChainEnd | kNodeFlagBlocksSplice,
                     .required_padding_left = 0,
                     .layer_group           = kNodeLayer4,
                     .layer_group_next_node = kNodeLayerNone,
                     .layer_group_prev_node = kNodeLayer4,
                     .can_have_next         = false,
                     .can_have_prev         = true};
}
