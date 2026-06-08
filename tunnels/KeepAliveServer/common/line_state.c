#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverLinestateInitialize(keepaliveserver_lstate_t *ls, line_t *l)
{
    *ls = (keepaliveserver_lstate_t) {
        .read_stream = bufferstreamCreate(lineGetBufferPool(l), kKeepAliveServerFramePrefixSize),
    };
}

void keepaliveserverLinestateDestroy(keepaliveserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(keepaliveserver_lstate_t)));
}
