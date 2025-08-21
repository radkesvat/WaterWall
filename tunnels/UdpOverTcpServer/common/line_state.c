#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverLinestateInitialize(udpovertcpserver_lstate_t *ls,buffer_pool_t *pool)
{
    ls->read_stream = bufferstreamCreate(pool, kHeaderSize);
}

void udpovertcpserverLinestateDestroy(udpovertcpserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, sizeof(udpovertcpserver_lstate_t));
}
