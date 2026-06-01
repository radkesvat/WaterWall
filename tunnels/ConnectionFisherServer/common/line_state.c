#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverLinestateInitialize(connectionfisherserver_lstate_t *ls, line_t *l)
{
    *ls = (connectionfisherserver_lstate_t) {
        .phase         = kConnectionFisherServerPhaseWaitPing,
        .next_init_sent = false,
        .in_stream     = bufferstreamCreate(lineGetBufferPool(l), 0),
    };
}

void connectionfisherserverLinestateDestroy(connectionfisherserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->in_stream);
    memoryZeroAligned32(ls, sizeof(*ls));
}
