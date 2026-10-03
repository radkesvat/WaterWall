#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (udpovertcpclient_lstate_t) {.read_stream = splicestreamCreate(pool, kHeaderSize), .pool = pool};
}

void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls)
{
    splicestreamDestroy(ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(udpovertcpclient_lstate_t)));
}
