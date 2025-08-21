#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls,buffer_pool_t *pool)
{
    ls->read_stream = bufferstreamCreate(pool, kHeaderSize);
}

void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, sizeof(udpovertcpclient_lstate_t));
}
