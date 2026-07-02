#include "structure.h"

#include "loggers/network_logger.h"

void pingclientLinestateInitialize(pingclient_lstate_t *ls)
{
    discard ls;
}

void pingclientLinestateDestroy(pingclient_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(pingclient_lstate_t)));
}
