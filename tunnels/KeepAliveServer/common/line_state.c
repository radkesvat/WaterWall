#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverLinestateInitialize(keepaliveserver_lstate_t *ls, line_t *l, bool splice_output)
{
    *ls = (keepaliveserver_lstate_t) {
        .pool = lineGetBufferPool(l),
    };
    spliceframereaderInit(&ls->reader,
                          ls->pool,
                          kKeepAliveServerFramePrefixSize,
                          kKeepAliveServerMaxReentryBytes,
                          kKeepAliveServerReadChargeLimit,
                          splice_output);
    bufferqueueInitEmpty(&ls->write_reentry);
}

void keepaliveserverLinestateDestroy(keepaliveserver_lstate_t *ls)
{
    if (ls->write_active != NULL)
        bufferpoolReuseBuffer(ls->pool, ls->write_active);
    bufferqueueDestroy(&ls->write_reentry);
    spliceframereaderDestroy(&ls->reader);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(keepaliveserver_lstate_t)));
}
