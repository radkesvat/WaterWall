#include "structure.h"

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind)
{
    *ls = (trojanserver_lstate_t) {
        .tunnel               = t,
        .line                 = l,
        .client_line          = NULL,
        .in_stream            = bufferstreamCreate(lineGetBufferPool(l), 0),
        .pending_down         = bufferqueueCreate(kTrojanServerBufferQueueCap),
        .udp_remote_lines     = trojanserver_remote_map_t_with_capacity(kTrojanServerRemoteMapCap),
        .user_handle          = userHandleEmpty(),
        .remote_key           = 0,
        .phase                = kTrojanServerPhaseWaitInitial,
        .line_kind            = kind,
        .branch               = kTrojanServerBranchNone,
        .client_line_locked   = false,
        .user_handle_recorded = false,
    };
}

void trojanserverLinestateDestroy(trojanserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_down);
    trojanserver_remote_map_t_drop(&ls->udp_remote_lines);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
