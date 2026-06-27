#include "structure.h"

void vlessclientLinestateInitialize(vlessclient_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (vlessclient_lstate_t) {.tunnel     = t,
                                  .line       = l,
                                  .in_stream  = bufferstreamCreate(lineGetBufferPool(l), 0),
                                  .pending_up = bufferqueueCreate(kVlessClientPendingQueueCap),
                                  .protocol   = kVlessClientProtocolTcp,
                                  .phase      = kVlessClientPhaseIdle,
                                  .kind       = kVlessClientLineKindDirect};
}

void vlessclientLinestateDestroy(vlessclient_lstate_t *ls)
{
    addresscontextReset(&ls->target_addr);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
