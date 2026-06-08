#include "structure.h"

#include "loggers/network_logger.h"

void testerserverLinestateInitialize(testerserver_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (testerserver_lstate_t) {.read_stream             = bufferstreamCreate(pool, 0),
                                   .response_queue          = bufferqueueCreate(8),
                                   .request_rx_index        = 0,
                                   .response_tx_index       = 0,
                                   .flow_id                 = 0,
                                   .response_ready          = false,
                                   .response_paused         = false,
                                   .response_send_scheduled = false,
                                   .response_sent           = false,
                                   .response_to_next        = false};
}

void testerserverLinestateDestroy(testerserver_lstate_t *ls)
{
    if (ls->read_stream.pool != NULL)
    {
        bufferstreamDestroy(&ls->read_stream);
    }
    bufferqueueDestroy(&ls->response_queue);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(testerserver_lstate_t)));
}
