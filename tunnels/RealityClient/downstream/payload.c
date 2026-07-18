#include "structure.h"

void realityclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_lstate_t *ls = lineGetState(l, t);

    if (ls->terminal_closing || ls->prev_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kRealityClientPhaseTls13AwaitAck)
    {
        realityclientProcessHandoffDownstream(t, l, buf);
        return;
    }

    if (ls->phase != kRealityClientPhaseRealityActive || ! ls->session_keys_ready)
    {
        lineReuseBuffer(l, buf);
        realityclientCloseLineBidirectional(t, l);
        return;
    }

    if (ls->handoff_completion_in_progress)
    {
        bufferstreamPush(&ls->read_stream, buf);
        return;
    }

    realityclientProcessDownstream(t, l, buf);
}
