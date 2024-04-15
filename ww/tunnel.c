#include "tunnel.h"
#include "string.h" // memset

extern line_t *newLine(uint16_t tid);
extern size_t reserveChainStateIndex(line_t *l);
extern void destroyLine(line_t *l);
extern void destroyContext(context_t *c);
extern context_t *newContext(line_t *line);
extern context_t *newContextFrom(context_t *source);
extern context_t *newEstContext(line_t *line);
extern context_t *newFinContext(line_t *line);
extern context_t *newInitContext(line_t *line);
extern context_t *switchLine(context_t *c, line_t *line);

void chain(tunnel_t *from, tunnel_t *to)
{
    assert(to->dw == NULL); // 2 nodes cannot chain to 1 exact node
    from->up = to;
    to->dw = from;
    to->chain_index = from->chain_index + 1;
}


tunnel_t *newTunnel()
{
    tunnel_t *t = malloc(sizeof(tunnel_t));
    t->state = NULL;
    t->dw = NULL;
    t->up = NULL;

    t->upStream = &defaultUpStream;
    t->packetUpStream = &defaultPacketUpStream;
    t->downStream = &defaultDownStream;
    t->packetDownStream = &defaultPacketDownStream;
    return t;
}

void defaultUpStream(tunnel_t *self, context_t *c)
{
    if (self->up != NULL)
    {
        self->up->upStream(self->up, c);
    }
}
void defaultPacketUpStream(tunnel_t *self, context_t *c)
{
    if (self->up != NULL)
    {
        self->up->packetUpStream(self->up, c);
    }
}

void defaultDownStream(tunnel_t *self, context_t *c)
{
    if (self->dw != NULL)
    {
        self->dw->downStream(self->dw, c);
    }
}
void defaultPacketDownStream(tunnel_t *self, context_t *c)
{
    if (self->dw != NULL)
    {
        self->dw->packetDownStream(self->dw, c);
    }
}
