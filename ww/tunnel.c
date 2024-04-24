#include "tunnel.h"
#include "string.h" // memset

extern line_t *       newLine(uint8_t tid);
extern uint8_t        reserveChainStateIndex(line_t *l);
extern void           destroyLine(line_t *l);
extern void           destroyContext(context_t *c);
extern void           internalUnRefLine(line_t *l);
extern bool           isAlive(line_t *line);
extern void           reuseContextBuffer(context_t *c);
extern bool           isFullyAuthenticated(line_t *line);
extern bool           isAuthenticated(line_t *line);
extern void           markAuthenticated(line_t *line);
extern void           markAuthenticationNodePresence(line_t *line);
extern context_t *    newContext(line_t *line);
extern context_t *    newContextFrom(context_t *source);
extern context_t *    newEstContext(line_t *line);
extern context_t *    newFinContext(line_t *line);
extern context_t *    newInitContext(line_t *line);
extern context_t *    switchLine(context_t *c, line_t *line);
extern buffer_pool_t *getThreadBufferPool(uint8_t tid);
extern buffer_pool_t *getLineBufferPool(line_t *l);
extern buffer_pool_t *getContextBufferPool(context_t *c);

// `from` upstreams to `to`
void chainUp(tunnel_t *from, tunnel_t *to)
{
    from->up = to;
}
// `to` downstreams to `from`
void chainDown(tunnel_t *from, tunnel_t *to)
{
    assert(to->dw == NULL); // 2 nodes cannot chain to 1 exact node
    to->dw = from;
}
// `from` <-> `to`
void chain(tunnel_t *from, tunnel_t *to)
{
    chainUp(from, to);
    chainDown(from, to);
    to->chain_index = from->chain_index + 1;
}

tunnel_t *newTunnel()
{
    tunnel_t *t = malloc(sizeof(tunnel_t));
    t->state    = NULL;
    t->dw       = NULL;
    t->up       = NULL;

    t->upStream   = &defaultUpStream;
    t->downStream = &defaultDownStream;
    return t;
}

void defaultUpStream(tunnel_t *self, context_t *c)
{
    if (self->up != NULL)
    {
        self->up->upStream(self->up, c);
    }
}

void defaultDownStream(tunnel_t *self, context_t *c)
{
    if (self->dw != NULL)
    {
        self->dw->downStream(self->dw, c);
    }
}
