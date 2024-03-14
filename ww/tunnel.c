#include "tunnel.h"
#include "string.h" // memset

void chain(tunnel_t *from, tunnel_t *to)
{
    assert(to->dw == NULL); // 2 nodes cannot chain to 1 exact node
    from->up = to;
    to->dw = from;
    to->chain_index = from->chain_index + 1;
}

line_t *newLine(size_t tid)
{
    size_t size = sizeof(line_t) + (sizeof(void *) * MAX_CHAIN_LEN);
    line_t *result = malloc(size);
    memset(result, 0, size);
    result->tid = tid;
    result->refc = 1;
    return result;
}
static inline void checkLine(line_t *l)
{
    if (l->refc > 0)
        return;

#ifdef DEBUG
    // there should not be any conn-state alive at this point
    for (size_t i = 0; i < MAX_CHAIN_LEN; i++)
    {
        assert(l->chains_state[i] == NULL);
    }
#endif

    free(l);

}

void destroyLine(line_t *l)
{
    l->refc -= 1;
    checkLine(l);
}

context_t *newContext(line_t *line)
{
    context_t *new_ctx = malloc(sizeof(context_t));
    memset(new_ctx, 0, sizeof(context_t));
    new_ctx->line = line;
    line->refc += 1;
    return new_ctx;
}

void destroyContext(context_t *c)
{
    assert(c->payload == NULL);
    if (c->dest_ctx.domain != NULL)
        free(c->dest_ctx.domain);
    destroyLine(c->line);

    free(c);
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
