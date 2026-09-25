#include "interface.h"

node_t nodeStreamFragmenterGet(void)
{
    const char *name = "StreamFragmenter";
    return (node_t) {
        .type                  = stringDuplicate(name),
        .hash_type             = calcHashBytes(name, stringLength(name)),
        .version               = 0001,
        .createHandle          = streamfragmenterTunnelCreate,
        .flags                 = kNodeFlagSupportsSplice,
        .required_padding_left = 0,
        .layer_group           = kNodeLayer4,
        .layer_group_next_node = kNodeLayer4,
        .layer_group_prev_node = kNodeLayer4,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
}
