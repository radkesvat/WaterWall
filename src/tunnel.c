#include "tunnel.h"
#include "string.h" // memset

void chain(tunnel_t *from, tunnel_t *to)
{
    from->up = to;
    to->dw = from;
    to->chain_index = from->chain_index + 1;
}

line_t *newLine()
{
    size_t size = sizeof(line_t) + (sizeof( void*)*MAX_CHAIN_LEN)  ;
    line_t *result = malloc(size);
    memset(result, 0, size);
}
void destroyLine(line_t *c)
{
    // we are not responsible for something we didnt allocate
    free(c);
}

context_t *newContext(line_t* line)
{
    context_t *new_ctx = malloc(sizeof(context_t));
    memset(new_ctx, 0, sizeof(context_t));
    new_ctx->line = line;

    return new_ctx;
}

void destroyContext(context_t *c)
{
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
