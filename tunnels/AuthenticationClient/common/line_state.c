#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientLinestateInitialize(authenticationclient_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (authenticationclient_lstate_t) {
        .read_stream = bufferstreamCreate(pool, 0),
    };
}

void authenticationclientLinestateDestroy(authenticationclient_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(authenticationclient_lstate_t)));
}
