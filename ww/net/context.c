#include "context.h"

void contextApplyOnTunnelU(context_t *c, tunnel_t *t)
{
    if (c->init)
    {
        t->fnInitU(t, c->line);
        return;
    }

    if (c->fin)
    {
        t->fnFinU(t, c->line);
        return;
    }

    if (c->est)
    {
        t->fnEstU(t, c->line);
        return;
    }

    if (c->pause)
    {
        t->fnPauseU(t, c->line);
        return;
    }

    if (c->resume)
    {
        t->fnResumeU(t, c->line);
        return;
    }
}

void contextApplyOnTunnelD(context_t *c, tunnel_t *t)
{
    if (c->init)
    {
        t->fnInitD(t, c->line);
        return;
    }

    if (c->fin)
    {
        t->fnFinD(t, c->line);
        return;
    }

    if (c->est)
    {
        t->fnEstD(t, c->line);
        return;
    }

    if (c->pause)
    {
        t->fnPauseD(t, c->line);
        return;
    }

    if (c->resume)
    {
        t->fnResumeD(t, c->line);
        return;
    }
}
