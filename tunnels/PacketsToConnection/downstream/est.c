#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    // not important, dosent worth locking the sack here
    discard t;
    discard l;
}
