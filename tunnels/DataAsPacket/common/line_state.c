#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketLinestateInitialize(dataaspacket_lstate_t *ls)
{
    discard ls;
}

void dataaspacketLinestateDestroy(dataaspacket_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(dataaspacket_lstate_t));
}
