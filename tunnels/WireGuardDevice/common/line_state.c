#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceLinestateInitialize(wireguarddevice_lstate_t *ls)
{
    (void) ls;
}

void wireguarddeviceLinestateDestroy(wireguarddevice_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(wireguarddevice_lstate_t));
}
