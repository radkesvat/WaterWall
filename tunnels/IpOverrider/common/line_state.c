#include "structure.h"

#include "loggers/network_logger.h"

void ipoverriderLinestateInitialize(ipoverrider_lstate_t *ls)
{
    discard ls;
}

void ipoverriderLinestateDestroy(ipoverrider_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(ipoverrider_lstate_t)));
}
