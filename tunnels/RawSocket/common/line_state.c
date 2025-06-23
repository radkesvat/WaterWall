#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketLinestateInitialize(rawsocket_lstate_t *ls)
{
    discard ls;
}

void rawsocketLinestateDestroy(rawsocket_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(rawsocket_lstate_t));
}
