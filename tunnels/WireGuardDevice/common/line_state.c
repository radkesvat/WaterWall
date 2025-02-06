#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceLinestateInitialize(wgd_lstate_t *ls)
{
    (void) ls;
}

void wireguarddeviceLinestateDestroy(wgd_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(wgd_lstate_t));
}
