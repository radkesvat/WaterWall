#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDownStreamFinish(tunnel_t *t, line_t *l)
{
    // This node dose not care about this callback
    discard t;
    discard l;
}
