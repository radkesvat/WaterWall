#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientLinestateInitialize(keepaliveclient_lstate_t *ls, line_t *l, bool splice_output)
{
    *ls = (keepaliveclient_lstate_t) {
        .pool = lineGetBufferPool(l),
        .line = l,
    };
    spliceframereaderInit(&ls->reader,
                          ls->pool,
                          kKeepAliveFramePrefixSize,
                          kKeepAliveMaxReentryBytes,
                          kKeepAliveReadChargeLimit,
                          splice_output);
    bufferqueueInitEmpty(&ls->write_reentry);
}

void keepaliveclientLinestateDestroy(keepaliveclient_lstate_t *ls)
{
    assert(ls->ping_item == NULL && ls->pong_deadline_item == NULL);
    if (ls->write_active != NULL)
        bufferpoolReuseBuffer(ls->pool, ls->write_active);
    bufferqueueDestroy(&ls->write_reentry);
    spliceframereaderDestroy(&ls->reader);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(keepaliveclient_lstate_t)));
}
