#include "TlsServer/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortTlsServerDrainingInitCase(void)
{
    // No SSL session is needed: even a draining fallback line must reject Init.
    tunnel_t *t = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
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
    l->alive                    = true;
    l->wid                      = 0;
    tlsserver_lstate_t *ls      = lineGetState(l, t);
    ls->fallback_mode           = true;
    ls->fallback_close_draining = true;
    t->fnInitD(t, l);

    memoryFreeAligned(l);
    tunnelDestroy(t);
    return 0;
}

int tunnelsAbortTlsServerClosingEstCase(void)
{
    // This valid line state previously absorbed the callback without terminating.
    tunnel_t *t = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
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
    l->alive               = true;
    l->wid                 = 0;
    tlsserver_lstate_t *ls = lineGetState(l, t);
    ls->upstream_finished  = true;
    t->fnEstU(t, l);

    memoryFreeAligned(l);
    tunnelDestroy(t);
    return 0;
}
