#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientLinestateInitialize(keepaliveclient_lstate_t *ls, line_t *l)
{
    *ls = (keepaliveclient_lstate_t) {
        .read_stream = splicestreamCreate(lineGetBufferPool(l), kKeepAliveFramePrefixSize),
        .pool        = lineGetBufferPool(l),
        .line        = l,
    };
    bufferqueueInitEmpty(&ls->write_reentry);
}

void keepaliveclientLinestateDestroy(keepaliveclient_lstate_t *ls)
{
    assert(ls->ping_item == NULL && ls->pong_deadline_item == NULL);
    if (ls->write_active != NULL)
        bufferpoolReuseBuffer(ls->pool, ls->write_active);
    bufferqueueDestroy(&ls->write_reentry);
    splicestreamDestroy(ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(keepaliveclient_lstate_t)));
}
