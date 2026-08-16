#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientLinestateInitialize(reverseclient_lstate_t *ls, reverseclient_pair_t *pair)
{
    *ls = (reverseclient_lstate_t) {.pair = pair};
}

void reverseclientLinestateDestroy(reverseclient_lstate_t *ls)
{

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(reverseclient_lstate_t)));
}
