#include "structure.h"

#include "loggers/network_logger.h"

void headerserverLinestateInitialize(headerserver_lstate_t *ls, line_t *l, headerserver_tstate_t *ts)
{
    *ls = (headerserver_lstate_t) {
        .phase       = (ts->override_mode == kHeaderServerOverrideModeHeaderPort) ? kHeaderServerPhaseWaitHeader
                                                                                  : kHeaderServerPhaseEstablished,
        .read_stream = bufferstreamCreate(lineGetBufferPool(l), 0),
    };
}

void headerserverLinestateDestroy(headerserver_lstate_t *ls)
{
    if (ls->phase == kHeaderServerPhaseNone)
    {
        return;
    }

    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, sizeof(*ls));
}
