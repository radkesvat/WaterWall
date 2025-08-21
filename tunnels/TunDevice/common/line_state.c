#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceLinestateInitialize(tundevice_lstate_t *ls)
{
    discard ls;
}

void tundeviceLinestateDestroy(tundevice_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(tundevice_lstate_t));
}
