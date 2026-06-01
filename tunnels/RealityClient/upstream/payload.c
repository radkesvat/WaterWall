#include "structure.h"

void realityclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    realityclient_lstate_t *ls = lineGetState(l, t);

    if (ls->next_finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! ls->tls_ready)
    {
        bufferqueuePushBack(&ls->pending_up, buf);
        return;
    }

    realityclientEncryptAndSend(t, l, buf);
}
