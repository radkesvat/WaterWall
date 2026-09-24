#include "interface.h"
#include "structure.h"

node_t nodeHttpProxyServerGet(void)
{
    const char *name = "HttpProxyServer";
    return (node_t) {.type                  = stringDuplicate(name),
                     .hash_type             = calcHashBytes(name, stringLength(name)),
                     .version               = 1,
                     .createHandle          = httpproxyserverTunnelCreate,
                     .flags                 = kNodeFlagSupportsSplice,
                     .required_padding_left = 0,
                     .layer_group           = kNodeLayer4,
                     .layer_group_next_node = kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
