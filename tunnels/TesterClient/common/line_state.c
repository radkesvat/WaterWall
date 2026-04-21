#include "structure.h"

#include "loggers/network_logger.h"

void testerclientLinestateInitialize(testerclient_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (testerclient_lstate_t) {
        .read_stream            = bufferstreamCreate(pool, 0),
        .request_tx_index       = 0,
        .response_rx_index      = 0,
        .flow_id                = 0,
        .est_received           = false,
        .request_paused         = false,
        .request_send_scheduled = false,
        .request_complete       = false,
        .response_complete      = false
    };
}

void testerclientLinestateDestroy(testerclient_lstate_t *ls)
{
    if (ls->read_stream.pool != NULL)
    {
        bufferstreamDestroy(&ls->read_stream);
    }

    memoryZeroAligned32(ls, sizeof(testerclient_lstate_t));
}
