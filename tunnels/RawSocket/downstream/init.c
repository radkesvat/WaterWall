#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("This Function is not supposed to be called (RawSocket)");
    exit(1);
}
