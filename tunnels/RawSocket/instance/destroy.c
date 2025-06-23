#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}

