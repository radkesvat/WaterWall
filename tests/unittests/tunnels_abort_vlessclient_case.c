#include "VlessClient/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortVlessClientUdpInitCase(void)
{
    // This valid line state previously absorbed the callback without terminating.
    tunnel_t *t = tunnelCreate(NULL, sizeof(vlessclient_tstate_t), sizeof(vlessclient_lstate_t));
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
    l->alive                 = true;
    l->wid                   = 0;
    vlessclient_lstate_t *ls = lineGetState(l, t);
    ls->kind                 = kVlessClientLineKindUdpApp;
    t->fnInitD(t, l);

    memoryFreeAligned(l);
    tunnelDestroy(t);
    return 0;
}
