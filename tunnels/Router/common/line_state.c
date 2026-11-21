#include "structure.h"

#include "modules/network/network.h"

void routerLinestateInitialize(router_lstate_t *ls, const address_context_t *dest)
{
    const uint8_t offer = routerNetworkOffer(dest);
    *ls                 = (router_lstate_t) {
                        .route               = kRouterRouteUndecided,
                        .network_offer       = offer,
                        .preserve_deliveries = (offer & kRouterNetworkUdp) != 0,
    };
    bufferqueueInitEmpty(&ls->datagrams);
}

void routerLinestateDestroy(line_t *l, router_lstate_t *ls)
{
    bufferqueueDestroy(&ls->datagrams);
    if (ls->pending != NULL)
    {
        // Sniff views for queued deliveries were allocated without a pool checkout.
        // Recycling them would incorrectly decrement the pool's debug in-use count.
        if (ls->preserve_deliveries)
            sbufDestroy(ls->pending);
        else
            lineReuseBuffer(l, ls->pending);
        ls->pending = NULL;
    }

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
