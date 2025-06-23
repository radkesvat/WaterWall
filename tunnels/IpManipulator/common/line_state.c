#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorLinestateInitialize(ipmanipulator_lstate_t *ls)
{
    discard ls;
}

void ipmanipulatorLinestateDestroy(ipmanipulator_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(ipmanipulator_lstate_t));
}
