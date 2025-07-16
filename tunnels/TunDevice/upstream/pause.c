#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    // This node dose not care about this callabck
    discard t;
    discard l;
}
