#include "structure.h"

void routerLinestateInitialize(router_lstate_t *ls)
{
    *ls = (router_lstate_t) {
        .pending            = NULL,
        .target             = NULL,
        .route              = kRouterRouteUndecided,
        .sniffed_attributes = 0,
    };
    bufferqueueInitEmpty(&ls->datagrams);
}

void routerLinestateDestroy(line_t *l, router_lstate_t *ls)
{
    bufferqueueDestroy(&ls->datagrams);
    if (ls->pending != NULL)
    {
        // UDP sniff views were allocated directly, without a pool checkout.
        // Recycling them would incorrectly decrement the pool's debug in-use count.
        if (ls->datagram_input)
            sbufDestroy(ls->pending);
        else
            lineReuseBuffer(l, ls->pending);
        ls->pending = NULL;
    }

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
