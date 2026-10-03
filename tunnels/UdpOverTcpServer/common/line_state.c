#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverLinestateInitialize(udpovertcpserver_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (udpovertcpserver_lstate_t) {
        .read_stream = splicestreamCreate(pool, kHeaderSize),
        .pool        = pool,
    };
}

void udpovertcpserverLinestateDestroy(udpovertcpserver_lstate_t *ls)
{
    splicestreamDestroy(ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(udpovertcpserver_lstate_t)));
}
