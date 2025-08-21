#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketLinestateInitialize(udpstatelesssocket_lstate_t *ls)
{
    discard ls;
}

void udpstatelesssocketLinestateDestroy(udpstatelesssocket_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(udpstatelesssocket_lstate_t));
}
