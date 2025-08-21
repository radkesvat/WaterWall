#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverLinestateInitialize(reverseserver_lstate_t *ls, line_t *u, line_t *d)
{

    *ls = (reverseserver_lstate_t) {
        .next       = NULL,
        .u          = u,
        .d          = d,
        .buffering  = NULL,
        .paired     = false,
        .handshaked = false,
    };
}

void reverseserverLinestateDestroy(reverseserver_lstate_t *ls)
{
    if (ls->buffering != NULL)
    {
        assert(false);
    }

    memoryZeroAligned32(ls, sizeof(reverseserver_lstate_t));
}
