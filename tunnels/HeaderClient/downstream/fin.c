#include "structure.h"

void headerclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    headerclientLinestateDestroy(lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}
