#include "interface.h"

node_t nodeSynReplyGet(void)
{
    const char *name = "SynReply";
    return (node_t) {
        .type                  = stringDuplicate(name),
        .hash_type             = calcHashBytes(name, stringLength(name)),
        .version               = 0001,
        .createHandle          = synreplyTunnelCreate,
        .required_padding_left = 0,
        .layer_group           = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .can_have_next         = true,
        .can_have_prev         = true,
    };
}
