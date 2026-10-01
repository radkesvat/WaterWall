#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverLinestateInitialize(keepaliveserver_lstate_t *ls, line_t *l)
{
    *ls = (keepaliveserver_lstate_t) {
        .read_stream = splicestreamCreate(lineGetBufferPool(l), kKeepAliveServerFramePrefixSize),
        .pool        = lineGetBufferPool(l),
    };
    bufferqueueInitEmpty(&ls->write_reentry);
}

void keepaliveserverLinestateDestroy(keepaliveserver_lstate_t *ls)
{
    if (ls->write_active != NULL)
        bufferpoolReuseBuffer(ls->pool, ls->write_active);
    bufferqueueDestroy(&ls->write_reentry);
    splicestreamDestroy(ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(keepaliveserver_lstate_t)));
}
