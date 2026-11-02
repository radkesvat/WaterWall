#include "internal.h"

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind)
{
    *ls = (trojanserver_lstate_t) {.tunnel = t, .line = l, .phase = kTrojanServerPhaseWaitInitial, .line_kind = kind};
    bufferbudgetInit(&ls->output_budget, (buffer_budget_cost_t) {kTrojanServerMaxPendingBytes, 8U * 1024U * 1024U});
    bufferqueueInitEmpty(&ls->pending_up);
    bufferreaderInit(&ls->reader, lineGetBufferPool(l), ls->header, sizeof(ls->header));
}

void trojanserverReleaseBuffers(trojanserver_lstate_t *ls)
{
    bufferreaderClear(&ls->reader);
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_up);
    fallbackReplayDestroy(&ls->fallback, lineGetBufferPool(ls->line));
    bufferbudgetAssertEmpty(&ls->output_budget);
    ls->selected_remote = NULL;
    memoryZero(ls->header, sizeof(ls->header));
}

void trojanserverLinestateDestroy(trojanserver_lstate_t *ls)
{
    trojanserverReleaseBuffers(ls);
    bufferreaderDestroy(&ls->reader);
    trojanserver_remote_map_t_drop(&ls->udp_remote_lines);
    memoryFree(ls->remote_key);
    memoryFree(ls->auth_username);
    memoryFree(ls->auth_password);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
