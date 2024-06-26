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

    const uint8_t new_to_chain_index = from->chain_index + 1;
    memcpy((uint8_t*)&(to->chain_index), &new_to_chain_index, sizeof(uint8_t));
}

tunnel_t *newTunnel(void)
{
    tunnel_t *ptr = malloc(sizeof(tunnel_t));

    tunnel_t tunnel = (tunnel_t){
        .upStream   = &defaultUpStream,
        .downStream = &defaultDownStream,
    };
    memcpy(ptr, &tunnel, sizeof(tunnel_t));

    return ptr;
}

pool_item_t *allocLinePoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return malloc(sizeof(line_t));
}
void destroyLinePoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    free(item);
}

pool_item_t *allocContextPoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return malloc(sizeof(context_t));
}

void destroyContextPoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    free(item);
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

void pipeUpStream(context_t *c)
{
    if (! pipeSendToUpStream((pipe_line_t *) c->line->up_state, c))
    {
        if (c->payload)
        {
            reuseContextBuffer(c);
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
            reuseContextBuffer(c);
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
void pipeTo(tunnel_t *self, line_t *l, uint8_t tid)
{
    assert(l->up_state == NULL);
    newPipeLine(self, l, tid, defaultPipeLocalUpStream, defaultPipeLocalDownStream);
}
