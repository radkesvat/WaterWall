#include "structure.h"

#include "loggers/network_logger.h"

void headerserverLinestateInitialize(headerserver_lstate_t *ls, line_t *l, headerserver_tstate_t *ts)
{
    bool waits_for_header = ts->override_mode == kHeaderServerOverrideModeHeaderPort ||
                            ts->override_mode == kHeaderServerOverrideModeProxyProtocolSourceFields;

    *ls = (headerserver_lstate_t) {
        .phase       = waits_for_header ? kHeaderServerPhaseWaitHeader : kHeaderServerPhaseEstablished,
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
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
