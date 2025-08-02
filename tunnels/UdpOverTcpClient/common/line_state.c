#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls)
{
    discard ls;
}

void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(udpovertcpclient_lstate_t));
}
