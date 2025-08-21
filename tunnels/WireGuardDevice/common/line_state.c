#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceLinestateInitialize(wgd_lstate_t *ls)
{
    discard ls;
}

void wireguarddeviceLinestateDestroy(wgd_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(wgd_lstate_t));
}
