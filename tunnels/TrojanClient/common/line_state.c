#include "internal.h"

void trojanclientLinestateInitialize(trojanclient_lstate_t *ls, line_t *l)
{
    *ls = (trojanclient_lstate_t) {.line = l, .phase = kTrojanClientPhaseIdle};
    bufferreaderInit(&ls->reader, lineGetBufferPool(l), ls->header, sizeof(ls->header));
}

void trojanclientLinestateDestroy(trojanclient_lstate_t *ls)
{
    firstPayloadWindowCancel(&ls->first_payload);
    addresscontextReset(&ls->target_addr);
    bufferreaderDestroy(&ls->reader);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
