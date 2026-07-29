#include "structure.h"

#include "loggers/network_logger.h"

void blackholeTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    // Absorbing this is the whole job. A chain-end sink borrows every line it is
    // handed: it owns no per-line state, so there is nothing to release, and it has
    // no next node, so there is nothing to forward to. The line's real owner drives
    // the close from here.
    discard l;
}
