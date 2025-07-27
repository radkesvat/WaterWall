#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls)
{
    discard ls;
}

void tlsclientLinestateDestroy(tlsclient_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(tlsclient_lstate_t));
}
