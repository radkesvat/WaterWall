#include "ConnectionStripeCommon/stripe.h"
#include "ConnectionStripeServer/interface.h"

node_t nodeConnectionStripeServerGet(void)
{
    const char *type = "ConnectionStripeServer";
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, stringLength(type)),
                     .version               = 1,
                     .createHandle          = connectionstripeserverTunnelCreate,
                     .flags                 = kNodeFlagSupportsSplice,
                     .required_padding_left = kStripeHeaderSize,
                     .layer_group           = kNodeLayer4,
                     .layer_group_next_node = kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
