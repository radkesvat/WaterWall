#include "structure.h"

#include "loggers/network_logger.h"

void blackholeLinestateInitialize(blackhole_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(blackhole_lstate_t));
}

void blackholeLinestateDestroy(blackhole_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(blackhole_lstate_t));
}
