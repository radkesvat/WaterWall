#include "structure.h"

void tlsclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (ls->upstream_finished)
    {
        return;
    }
    ls->next_paused = false;
    if (ls->shaping_producer_paused || ls->plaintext_producer_paused)
    {
        return;
    }
    ls->source_paused = false;
    tunnelPrevDownStreamResume(t, l);
}
