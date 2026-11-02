#include "structure.h"

#include "loggers/network_logger.h"

void headerserverLinestateInitialize(headerserver_lstate_t *ls, line_t *l, headerserver_tstate_t *ts)
{
    bool waits_for_header = ts->override_mode == kHeaderServerOverrideModeHeaderPort ||
                            ts->override_mode == kHeaderServerOverrideModeHeaderProtocol ||
                            ts->override_mode == kHeaderServerOverrideModeProxyProtocolSourceFields;

    *ls = (headerserver_lstate_t) {
        .phase           = waits_for_header ? kHeaderServerPhaseWaitHeader : kHeaderServerPhaseEstablished,
        .read_stream     = bufferstreamCreate(lineGetBufferPool(l), 0),
    };
    nextinitgateInit(&ls->gate, kHeaderServerMaxReentryBytes, kHeaderServerMaxReentryCharge);
}

void headerserverLinestateDestroy(headerserver_lstate_t *ls)
{
    assert(ls->phase != kHeaderServerPhaseNone);

    nextinitgateDestroy(&ls->gate, ls->read_stream.pool);
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
