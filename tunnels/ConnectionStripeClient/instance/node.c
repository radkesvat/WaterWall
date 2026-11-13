#include "ConnectionStripeClient/interface.h"
#include "ConnectionStripeCommon/stripe.h"

node_t nodeConnectionStripeClientGet(void)
{
    const char *type = "ConnectionStripeClient";
    return (node_t) {.type                  = stringDuplicate(type),
                     .hash_type             = calcHashBytes(type, stringLength(type)),
                     .version               = 1,
                     .createHandle          = connectionstripeclientTunnelCreate,
                     .flags                 = kNodeFlagBlocksSplice,
                     .required_padding_left = kStripeHeaderSize,
                     .layer_group           = kNodeLayer4,
                     .layer_group_next_node = kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4,
                     .can_have_next         = true,
                     .can_have_prev         = true};
}
