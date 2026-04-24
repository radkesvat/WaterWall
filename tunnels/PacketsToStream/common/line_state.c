#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamLinestateInitialize(packetstostream_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (packetstostream_lstate_t) {.line        = NULL,
                                      .read_stream = bufferstreamCreate(pool, kHeaderSize),
                                      .ping_sent_at_ms = 0,
                                      .pong_deadline_ms = 0,
                                      .paused      = false,
                                      .awaiting_pong = false,
                                      .recreate_scheduled = false};
}

void packetstostreamLinestateDestroy(packetstostream_lstate_t *ls)
{
    if (ls->read_stream.pool != NULL)
    {
        bufferstreamDestroy(&ls->read_stream);
    }

    memoryZeroAligned32(ls, sizeof(packetstostream_lstate_t));
}
