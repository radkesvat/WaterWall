#include "structure.h"

void routerLinestateInitialize(router_lstate_t *ls)
{
    *ls = (router_lstate_t) {
        .pending = NULL,
        .target  = NULL,
        .decided = kRouterRouteUndecided,
    };
}

void routerLinestateDestroy(line_t *l, router_lstate_t *ls)
{
    if (ls->pending != NULL)
    {
        lineReuseBuffer(l, ls->pending);
        ls->pending = NULL;
    }

    memorySet(ls, 0, sizeof(*ls));
}
