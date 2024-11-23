#include "tunnel.h"
#include "pipe_line.h"
#include "string.h" // memset
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

// `from` upstreams to `to`
void chainUp(tunnel_t *from, tunnel_t *to)
{
    from->up = to;
}

// `to` downstreams to `from`
void chainDown(tunnel_t *from, tunnel_t *to)
{
    // assert(to->dw == NULL); // 2 nodes cannot chain to 1 exact node
    // such chains are possible by a generic listener adapter
    // but the cyclic refrence detection is already done in node map
    to->dw = from;
}

// `from` <-> `to`
void chain(tunnel_t *from, tunnel_t *to)
{
    chainUp(from, to);
    chainDown(from, to);

    to->chain_index = from->chain_index + 1;
}

tunnel_t *newTunnel(void)
{
    tunnel_t *ptr = globalMalloc(sizeof(tunnel_t));

    tunnel_t tunnel = (tunnel_t) {
        .upStream   = &defaultUpStream,
        .downStream = &defaultDownStream,
    };
    memcpy(ptr, &tunnel, sizeof(tunnel_t));

    return ptr;
}

pool_item_t *allocLinePoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return globalMalloc(sizeof(line_t));
}

void destroyLinePoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    globalFree(item);
}

pool_item_t *allocContextPoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return globalMalloc(sizeof(context_t));
}

void destroyContextPoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    globalFree(item);
}

void defaultUpStreamInit(tunnel_t *self, line_t *line)
{
    if (self->up != NULL)
    {
        self->up->fnInitU(self->up, line);
    }
}

void defaultUpStreamEst(tunnel_t *self, line_t *line)
{
    if (self->up != NULL)
    {
        self->up->fnEstU(self->up, line);
    }
}

void defaultUpStreamFin(tunnel_t *self, line_t *line)
{
    if (self->up != NULL)
    {
        self->up->fnFinU(self->up, line);
    }
}
void defaultUpStreamPayload(tunnel_t *self, line_t *line, shift_buffer_t *payload)
{
    if (self->up != NULL)
    {
        self->up->fnPayloadU(self->up, line, payload);
    }
}

void defaultdownStreamInit(tunnel_t *self, line_t *line)
{
    if (self->up != NULL)
    {
        self->up->fnInitD(self->up, line);
    }
}

void defaultdownStreamEst(tunnel_t *self, line_t *line)
{
    if (self->up != NULL)
    {
        self->up->fnEstD(self->up, line);
    }
}

void defaultdownStreamFin(tunnel_t *self, line_t *line)
{
    if (self->up != NULL)
    {
        self->up->fnFinD(self->up, line);
    }
}
void defaultdownStreamPayload(tunnel_t *self, line_t *line, shift_buffer_t *payload)
{
    if (self->up != NULL)
    {
        self->up->fnPayloadD(self->up, line, payload);
    }
}

void pipeUpStream(context_t *c)
{
    if (! pipeSendToUpStream((pipe_line_t *) c->line->up_state, c))
    {
        if (c->payload)
        {
            reuseContextPayload(c);
        }
        destroyContext(c);
    }
}

void pipeDownStream(context_t *c)
{
    if (! pipeSendToDownStream((pipe_line_t *) c->line->dw_state, c))
    {
        if (c->payload)
        {
            reuseContextPayload(c);
        }
        destroyContext(c);
    }
}

static void defaultPipeLocalUpStream(struct tunnel_s *self, struct context_s *c, struct pipe_line_s *pl)
{
    (void) pl;
    if (isUpPiped(c->line))
    {
        pipeUpStream(c);
    }
    else
    {
        self->upStream(self, c);
    }
}

static void defaultPipeLocalDownStream(struct tunnel_s *self, struct context_s *c, struct pipe_line_s *pl)
{
    (void) pl;
    if (isDownPiped(c->line))
    {
        pipeDownStream(c);
    }
    else
    {
        self->dw->downStream(self->dw, c);
    }
}

void pipeTo(tunnel_t *self, line_t *l, tid_t tid)
{
    assert(l->up_state == NULL);
    newPipeLine(self, l, tid, defaultPipeLocalUpStream, defaultPipeLocalDownStream);
}
