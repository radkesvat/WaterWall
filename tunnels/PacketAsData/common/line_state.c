#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataLinestateInitialize(packetasdata_lstate_t *ls)
{
    discard ls;
}

void packetasdataLinestateDestroy(packetasdata_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(packetasdata_lstate_t));
}
