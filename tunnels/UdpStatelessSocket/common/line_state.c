#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketLinestateInitialize(udpstatelesssocket_lstate_t *ls)
{
    discard ls;
}

void udpstatelesssocketLinestateDestroy(udpstatelesssocket_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(udpstatelesssocket_lstate_t));
}
