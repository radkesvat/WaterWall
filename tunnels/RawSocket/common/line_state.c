#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketLinestateInitialize(rawsocket_lstate_t *ls)
{
    discard ls;
}

void rawsocketLinestateDestroy(rawsocket_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(rawsocket_lstate_t));
}
