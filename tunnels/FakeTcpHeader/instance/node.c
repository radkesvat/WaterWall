#include "interface.h"
#include "structure.h"

node_t nodeFakeTcpHeaderGet(void)
{
    const char *type_name = "FakeTcpHeader";
    return (node_t){
        .type                  = stringDuplicate(type_name),
        .hash_type             = calcHashBytes(type_name, stringLength(type_name)),
        .version               = 0001,
        .createHandle          = faketcpheaderCreate,
        .flags                 = kNodeFlagNone,
        .required_padding_left = kFakeTcpHeaderPadding,
        .layer_group           = kNodeLayer3,
        .layer_group_prev_node = kNodeLayer3,
        .layer_group_next_node = kNodeLayer3,
        .can_have_prev         = true,
        .can_have_next         = true,
    };
}
