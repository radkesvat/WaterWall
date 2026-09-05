#include "RealityServer/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortRealityServerClosingEstCase(void)
{
    // This valid line state previously absorbed the callback without terminating.
    tunnel_t *t = tunnelCreate(NULL, sizeof(realityserver_tstate_t), sizeof(realityserver_lstate_t));
    if (t == NULL)
    {
        return kAbortCaseAllocationFailed;
    }
    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + t->lstate_size);
    if (l == NULL)
    {
        tunnelDestroy(t);
        return kAbortCaseAllocationFailed;
    }
    atomic_init(&l->refc, 1);
    l->alive                   = true;
    l->wid                     = 0;
    realityserver_lstate_t *ls = lineGetState(l, t);
    ls->terminal_closing       = true;
    t->fnEstU(t, l);

    memoryFreeAligned(l);
    tunnelDestroy(t);
    return 0;
}
