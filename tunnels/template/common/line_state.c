#include "structure.h"

#include "loggers/network_logger.h"

void templateLinestateInitialize(template_lstate_t *ls)
{
    (void) ls;
}

void templateLinestateDestroy(template_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(template_lstate_t));
}
