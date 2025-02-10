#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceLinestateInitialize(tundevice_lstate_t *ls)
{
    (void) ls;
}

void tundeviceLinestateDestroy(tundevice_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(tundevice_lstate_t));
}
