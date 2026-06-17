#include "structure.h"

void trojanclientLinestateInitialize(trojanclient_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (trojanclient_lstate_t) {.tunnel      = t,
                                   .line        = l,
                                   .dns_request = NULL,
                                   .in_stream   = bufferstreamCreate(lineGetBufferPool(l), 0),
                                   .pending_up  = bufferqueueCreate(kTrojanClientPendingQueueCap),
                                   .protocol    = kTrojanClientProtocolTcp,
                                   .phase       = kTrojanClientPhaseIdle,
                                   .kind        = kTrojanClientLineKindDirect};
}

void trojanclientCancelDnsRequest(trojanclient_lstate_t *ls)
{
    if (ls->dns_request != NULL)
    {
        ls->dns_request->cancelled = true;
        ls->dns_request            = NULL;
    }
}

void trojanclientLinestateDestroy(trojanclient_lstate_t *ls)
{
    trojanclientCancelDnsRequest(ls);
    addresscontextReset(&ls->target_addr);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
