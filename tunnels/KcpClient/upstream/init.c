#include "structure.h"

void kcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    if (! kcpclientSessionCreate(t, l))
        tunnelPrevDownStreamFinish(t, l);
}
