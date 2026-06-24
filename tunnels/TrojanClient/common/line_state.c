#include "structure.h"

void trojanclientLinestateInitialize(trojanclient_lstate_t *ls, tunnel_t *t, line_t *l)
{
    *ls = (trojanclient_lstate_t) {.tunnel     = t,
                                   .line       = l,
                                   .in_stream  = bufferstreamCreate(lineGetBufferPool(l), 0),
                                   .pending_up = bufferqueueCreate(kTrojanClientPendingQueueCap),
                                   .protocol   = kTrojanClientProtocolTcp,
                                   .phase      = kTrojanClientPhaseIdle,
                                   .kind       = kTrojanClientLineKindDirect};
}

void trojanclientLinestateDestroy(trojanclient_lstate_t *ls)
{
    addresscontextReset(&ls->target_addr);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

void trojanclientDomainSetupLinestateInitialize(trojanclient_domain_setup_lstate_t *ls)
{
    *ls = (trojanclient_domain_setup_lstate_t) {.protocol = kTrojanClientProtocolTcp};
}

void trojanclientDomainSetupLinestateDestroy(trojanclient_domain_setup_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(trojanclient_domain_setup_lstate_t)));
}
