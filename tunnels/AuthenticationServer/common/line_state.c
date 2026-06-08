#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverLinestateInitialize(authenticationserver_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (authenticationserver_lstate_t) {.read_stream     = bufferstreamCreate(pool, 0),
                                           .response_queue  = bufferqueueCreate(kAuthenticationServerResponseQueueCap),
                                           .response_paused = false};
}

void authenticationserverLinestateDestroy(authenticationserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    bufferqueueDestroy(&ls->response_queue);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(authenticationserver_lstate_t)));
}
