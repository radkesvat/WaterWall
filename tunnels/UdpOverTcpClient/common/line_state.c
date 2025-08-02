#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls,buffer_pool_t *pool)
{
    ls->read_stream = bufferstreamCreate(pool, kLeftPaddingSize);
}

void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memorySet(ls, 0, sizeof(udpovertcpclient_lstate_t));
}
