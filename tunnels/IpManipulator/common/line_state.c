#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorLinestateInitialize(ipmanipulator_lstate_t *ls)
{
    discard ls;
}

void ipmanipulatorLinestateDestroy(ipmanipulator_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(ipmanipulator_lstate_t)));
}
