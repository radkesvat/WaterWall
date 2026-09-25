#include "interface.h"
#include "structure.h"
node_t nodeHttpProxyClientGet(void)
{
    const char *name = "HttpProxyClient";
    return (node_t) {.type                  = stringDuplicate(name),
                     .hash_type             = calcHashBytes(name, stringLength(name)),
                     .version               = 1,
                     .createHandle          = httpproxyclientTunnelCreate,
                     .flags                 = kNodeFlagSupportsSplice,
                     .required_padding_left = kHpcRequiredPaddingLeft,
                     .layer_group           = kNodeLayer4,
                     .layer_group_next_node = kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
