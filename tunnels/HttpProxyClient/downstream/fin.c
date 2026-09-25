#include "loggers/network_logger.h"
#include "structure.h"
void httpproxyclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
    {
        ls->next_finished = true;
        return;
    }
    hpc_tstate_t *ts = tunnelGetState(t);
    if (ts->verbose &&
        (! ls->accepted || (! ts->connect && ls->body.kind != kHpsBodyEof && ls->body.kind != kHpsBodyDone)))
        LOGD("HttpProxyClient: response truncated");
    hpcDestroyState(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
