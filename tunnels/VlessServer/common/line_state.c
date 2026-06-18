#include "structure.h"

void vlessserverLinestateInitialize(vlessserver_lstate_t *ls, tunnel_t *t, line_t *l, vlessserver_line_kind_t kind)
{
    *ls = (vlessserver_lstate_t) {
        .tunnel               = t,
        .line                 = l,
        .client_line          = NULL,
        .udp_remote_line      = NULL,
        .in_stream            = bufferstreamCreate(lineGetBufferPool(l), 0),
        .pending_down         = bufferqueueCreate(kVlessServerBufferQueueCap),
        .user_handle          = userHandleEmpty(),
        .auth_username        = NULL,
        .auth_password        = NULL,
        .phase                = kVlessServerPhaseWaitInitial,
        .line_kind            = kind,
        .client_line_locked   = false,
        .response_sent        = false,
        .user_handle_recorded = false,
    };
}

void vlessserverLinestateDestroy(vlessserver_lstate_t *ls)
{
    addresscontextReset(&ls->udp_target);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_down);
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
