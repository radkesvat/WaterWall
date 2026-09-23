#include "structure.h"

void vlessclientLinestateInitialize(vlessclient_lstate_t *ls, line_t *l)
{
    *ls = (vlessclient_lstate_t) {.line = l, .phase = kVlessClientPhaseIdle, .header_needed = 2};
    bufferqueueInitEmpty(&ls->pending_down);
}

void vlessclientLinestateDestroy(vlessclient_lstate_t *ls)
{
    vlessclientCancelFirstPayloadTimer(ls);
    addresscontextReset(&ls->target_addr);
    if (ls->receive_head != NULL)
        lineReuseBuffer(ls->line, ls->receive_head);
    bufferqueueDestroy(&ls->pending_down);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
