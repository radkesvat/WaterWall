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
    if (ls->in_stream.pool != NULL)
        bufferstreamDestroy(&ls->in_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

void connectionfisherserverRetireReadStream(connectionfisherserver_lstate_t *ls)
{
    assert(bufferstreamIsEmpty(&ls->in_stream));
    bufferstreamDestroy(&ls->in_stream);
    ls->in_stream = (buffer_stream_t) {0};
}
