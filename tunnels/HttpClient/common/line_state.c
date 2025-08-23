#include "structure.h"

#include "loggers/network_logger.h"

void httpclientLinestateInitialize(httpclient_lstate_t *ls)
{
    discard ls;
}

void httpclientLinestateDestroy(httpclient_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(httpclient_lstate_t));
}
