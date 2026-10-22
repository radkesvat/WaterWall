#include "structure.h"

void headerclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    headerclientLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
}
