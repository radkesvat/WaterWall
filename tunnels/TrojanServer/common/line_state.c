#include "structure.h"

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind)
{
    *ls = (trojanserver_lstate_t) {
        .tunnel                     = t,
        .line                       = l,
        .client_line                = NULL,
        .in_stream                  = bufferstreamCreate(lineGetBufferPool(l), 0),
        .pending_down               = bufferqueueCreate(kTrojanServerBufferQueueCap),
        .fallback_pending_up        = NULL,
        .udp_remote_lines           = trojanserver_remote_map_t_with_capacity(kTrojanServerRemoteMapCap),
        .user_handle                = userHandleEmpty(),
        .auth_username              = NULL,
        .auth_password              = NULL,
        .remote_key                 = 0,
        .phase                      = kTrojanServerPhaseWaitInitial,
        .line_kind                  = kind,
        .branch                     = kTrojanServerBranchNone,
        .client_line_locked         = false,
        .user_handle_recorded       = false,
        .fallback_up_finish_pending = false,
        .fallback_up_finished       = false,
        .fallback_delay_scheduled   = false,
    };
}

void trojanserverLinestateDestroy(trojanserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_down);
    if (ls->fallback_pending_up != NULL)
    {
        bufferqueueDestroy(ls->fallback_pending_up);
        memoryFree(ls->fallback_pending_up);
    }
    trojanserver_remote_map_t_drop(&ls->udp_remote_lines);
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
