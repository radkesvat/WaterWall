#include "structure.h"

void trojanclientLinestateInitialize(trojanclient_lstate_t *ls, line_t *l)
{
    *ls = (trojanclient_lstate_t) {.line = l, .phase = kTrojanClientPhaseIdle, .header_needed = 1};
    bufferqueueInitEmpty(&ls->pending_down);
}

void trojanclientLinestateDestroy(trojanclient_lstate_t *ls)
{
    trojanclientCancelFirstPayloadTimer(ls);
    addresscontextReset(&ls->target_addr);
    if (ls->receive_head != NULL)
        lineReuseBuffer(ls->line, ls->receive_head);
    bufferqueueDestroy(&ls->pending_down);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
