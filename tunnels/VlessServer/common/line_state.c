#include "structure.h"

void vlessserverLinestateInitialize(vlessserver_lstate_t *ls, tunnel_t *t, line_t *l, vlessserver_line_kind_t kind)
{
    *ls = (vlessserver_lstate_t) {
        .tunnel      = t,
        .line        = l,
        .user_handle = userHandleEmpty(),
        .phase       = kVlessServerPhaseWaitInitial,
        .line_kind   = kind,
    };
    bufferqueueInitEmpty(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_down);
    buffer_budget_cost_t limits = {kVlessServerMaxPendingBytes, SIZE_MAX, kVlessServerMaxPendingBuffers};
    bufferbudgetInit(&ls->upstream_budget, limits);
    bufferbudgetInit(&ls->response_budget, limits);
    bool attached = bufferqueueTryAttachBudget(&ls->pending_down, &ls->response_budget);
    assert(attached);
    discard attached;
}

void vlessserverLinestateDestroy(vlessserver_lstate_t *ls)
{
    addresscontextReset(&ls->udp_target);
    if (ls->input_head != NULL)
        lineReuseBuffer(ls->line, ls->input_head);
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueDestroy(&ls->pending_down);
    if (ls->fallback_pending_up != NULL)
    {
        bufferqueueDestroy(ls->fallback_pending_up);
        memoryFree(ls->fallback_pending_up);
    }
    bufferbudgetAssertEmpty(&ls->upstream_budget);
    bufferbudgetAssertEmpty(&ls->response_budget);
    if (ls->auth_username != NULL)
    {
        memoryFree(ls->auth_username);
    }
    if (ls->auth_password != NULL)
    {
        memoryFree(ls->auth_password);
    }
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
