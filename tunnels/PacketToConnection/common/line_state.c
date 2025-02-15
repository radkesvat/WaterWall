#include "structure.h"

#include "loggers/network_logger.h"

void ptcLinestateInitialize(ptc_lstate_t *ls)
{
    (void) ls;
}

void ptcLinestateDestroy(ptc_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(ptc_lstate_t));
}
