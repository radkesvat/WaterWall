#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientLinestateInitialize(keepaliveclient_lstate_t *ls, line_t *l)
{
    *ls = (keepaliveclient_lstate_t) {
        .read_stream  = bufferstreamCreate(lineGetBufferPool(l), kKeepAliveFramePrefixSize),
        .line         = l,
        .tracked_prev = NULL,
        .tracked_next = NULL,
        .wid          = lineGetWID(l),
    };
}

void keepaliveclientLinestateDestroy(keepaliveclient_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(keepaliveclient_lstate_t)));
}
