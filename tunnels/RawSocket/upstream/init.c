#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    //at the begining of progarm this may get called once, ignoring on packet tunnels
}
