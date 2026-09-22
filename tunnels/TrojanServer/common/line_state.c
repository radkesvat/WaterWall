#include "structure.h"

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind)
{
    *ls = (trojanserver_lstate_t) {
        .tunnel = t, .line = l, .phase = kTrojanServerPhaseWaitInitial, .line_kind = kind, .header_needed = 56};
    bufferqueueInitEmpty(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_down);
}

void trojanserverReleaseBuffers(trojanserver_lstate_t *ls)
{
    if (ls->input_head != NULL)
        lineReuseBuffer(ls->line, ls->input_head);
    ls->input_head  = NULL;
    ls->input_bytes = 0;
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_up);
    bufferqueueDestroy(&ls->pending_down);
    bufferqueueInitEmpty(&ls->pending_down);
    if (ls->fallback_pending_up != NULL)
    {
        bufferqueueDestroy(ls->fallback_pending_up);
        memoryFree(ls->fallback_pending_up);
        ls->fallback_pending_up = NULL;
    }
    while (ls->reply_head != NULL)
    {
        trojanserver_reply_t *reply = ls->reply_head;
        ls->reply_head              = reply->next;
        lineReuseBuffer(ls->line, reply->buf);
        memoryFree(reply);
    }
    addresscontextReset(&ls->frame_target);
    ls->reply_tail      = NULL;
    ls->reply_bytes     = 0;
    ls->reply_count     = 0;
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
