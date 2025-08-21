#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataLinestateInitialize(packetasdata_lstate_t *ls)
{
    discard ls;
}

void packetasdataLinestateDestroy(packetasdata_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(packetasdata_lstate_t));
}
