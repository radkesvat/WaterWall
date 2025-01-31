#include "context.h"


void contextApplyOnTunnelU(context_t *c,tunnel_t* t){
    t->fnInitU(t,c->line);
    t->fnEstU(t,c->line);
    t->fnFinU(t,c->line);
    t->fnPayloadU(t,c->line,c->payload);
    t->fnPauseU(t,c->line);
    t->fnResumeU(t,c->line);
}

void contextApplyOnTunnelD(context_t *c, tunnel_t *t){
    t->fnInitD(t,c->line);
    t->fnEstD(t,c->line);
    t->fnFinD(t,c->line);
    t->fnPayloadD(t,c->line,c->payload);
    t->fnPauseD(t,c->line);
    t->fnResumeD(t,c->line);
}
