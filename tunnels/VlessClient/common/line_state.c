#include "internal.h"

void vlessclientLinestateInitialize(vlessclient_lstate_t *ls, line_t *l)
{
    *ls = (vlessclient_lstate_t) {.line = l, .phase = kVlessClientPhaseIdle};
    bufferreaderInit(&ls->reader, lineGetBufferPool(l), ls->header, sizeof(ls->header));
}

void vlessclientLinestateDestroy(vlessclient_lstate_t *ls)
{
    firstPayloadWindowCancel(&ls->first_payload);
    addresscontextReset(&ls->target_addr);
    bufferreaderDestroy(&ls->reader);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
