#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverLinestateInitialize(connectionfisherserver_lstate_t *ls, line_t *l)
{
    *ls = (connectionfisherserver_lstate_t) {
        .phase          = kConnectionFisherServerPhaseWaitPing,
        .next_init_sent = false,
        .in_stream      = bufferstreamCreate(lineGetBufferPool(l), 0),
    };
    bufferqueueInitEmpty(&ls->pending_up);
}

void connectionfisherserverLinestateDestroy(connectionfisherserver_lstate_t *ls)
{
    bufferqueueDestroy(&ls->pending_up);
    bufferstreamDestroy(&ls->in_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
