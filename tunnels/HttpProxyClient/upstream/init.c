#include "structure.h"
void httpproxyclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    hpc_tstate_t *ts = tunnelGetState(t);
    hpc_lstate_t *ls = lineGetState(l, t);
    *ls              = (hpc_lstate_t) {
                     .t = t, .line = l, .init_busy = true, .upload_remaining = ts->content_length, .progress_at = hpcNow(l)};
    for (unsigned d = 0; d < 2; ++d)
    {
        bufferqueueInitEmpty(&ls->pending[d]);
        bufferbudgetInit(&ls->budgets[d],
                         (buffer_budget_cost_t) {kHpcDeliveryLimit, kHpcDeliveryLimit, kHpcPendingEntries});
        bool attached = bufferqueueTryAttachBudget(&ls->pending[d], &ls->budgets[d]);
        assert(attached);
        discard attached;
    }
    if (! hpcAllowed(t, l) || ! hpcBuildRequest(t, l))
    {
        hpcClose(t, l);
        return;
    }
    ls->carry = memoryAllocate((size_t) max(ts->max_header, kHpsTrailerLimit) + 1);
    if (! ls->carry || ! hpcStartTimer(t, l))
    {
        hpcClose(t, l);
        return;
    }
    ls->next_init = true;
    if (! lineCallWithRef(l, tunnelNextUpStreamInit, t))
        return;
    ls->init_busy = false;
    if (! hpcSendHeader(t, l) || ! hpcDrainUpload(t, l))
        return;
    hpcPressure(t, l);
}
