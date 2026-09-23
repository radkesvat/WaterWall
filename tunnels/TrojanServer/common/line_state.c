#include "structure.h"

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind)
{
    *ls = (trojanserver_lstate_t) {
        .tunnel = t, .line = l, .phase = kTrojanServerPhaseWaitInitial, .line_kind = kind, .header_needed = 56};
    bufferbudgetInit(&ls->output_budget,
                     (buffer_budget_cost_t) {kTrojanServerMaxPendingBytes, SIZE_MAX, kTrojanServerMaxQueuedBuffers});
    bufferqueueInitEmpty(&ls->pending_up);
}

void trojanserverReleaseBuffers(trojanserver_lstate_t *ls)
{
    if (ls->input_head != NULL)
        lineReuseBuffer(ls->line, ls->input_head);
    ls->input_head  = NULL;
    ls->input_bytes = 0;
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_up);
    if (ls->fallback_pending_up != NULL)
    {
        bufferqueueDestroy(ls->fallback_pending_up);
        memoryFree(ls->fallback_pending_up);
        ls->fallback_pending_up = NULL;
    }
    bufferbudgetAssertEmpty(&ls->output_budget);
    addresscontextReset(&ls->frame_target);
    ls->selected_remote = NULL;
    ls->header_filled   = 0;
    memoryZero(ls->header, sizeof(ls->header));
}

void trojanserverLinestateDestroy(trojanserver_lstate_t *ls)
{
    trojanserverReleaseBuffers(ls);
    trojanserver_remote_map_t_drop(&ls->udp_remote_lines);
    memoryFree(ls->auth_username);
    memoryFree(ls->auth_password);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
