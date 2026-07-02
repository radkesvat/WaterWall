#include "structure.h"

#include "loggers/network_logger.h"

void pingserverLinestateInitialize(pingserver_lstate_t *ls)
{
    discard ls;
}

void pingserverLinestateDestroy(pingserver_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(pingserver_lstate_t)));
}
