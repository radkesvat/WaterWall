#include "context.h"

/*
 * Dispatches context events to upstream or downstream tunnel callbacks.
 */

void contextApplyOnTunnelU(context_t *c, tunnel_t *t)
{
    if (c->payload)
    {
        tunnelUpStreamPayload(t, c->line, c->payload);
        c->payload = NULL; // Clear payload after applying
        return;
    }
    if (c->init)
    {
        tunnelUpStreamInit(t, c->line);
        return;
    }

    if (c->fin)
    {
        tunnelUpStreamFin(t, c->line);
        return;
    }

    if (c->est)
    {
        tunnelUpStreamEst(t, c->line);
        return;
    }

    if (c->pause)
    {
        tunnelUpStreamPause(t, c->line);
        return;
    }

    if (c->resume)
    {
        tunnelUpStreamResume(t, c->line);
        return;
    }
    assert(false);
}

void contextApplyOnTunnelD(context_t *c, tunnel_t *t)
{
    if (c->payload)
    {
        tunnelDownStreamPayload(t, c->line, c->payload);
        c->payload = NULL; // Clear payload after applying
        return;
    }
    if (c->init)
    {
        tunnelDownStreamInit(t, c->line);
        return;
    }

    if (c->fin)
    {
        tunnelDownStreamFin(t, c->line);
        return;
    }

    if (c->est)
    {
        tunnelDownStreamEst(t, c->line);
        return;
    }

    if (c->pause)
    {
        tunnelDownStreamPause(t, c->line);
        return;
    }

    if (c->resume)
    {
        tunnelDownStreamResume(t, c->line);
        return;
    }
    assert(false);

}
