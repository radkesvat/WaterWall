#include "structure.h"

#include "loggers/network_logger.h"

void bridgeLinestateInitialize(bridge_lstate_t *ls)
{
    discard ls;
}

void bridgeLinestateDestroy(bridge_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(bridge_lstate_t)));
}
