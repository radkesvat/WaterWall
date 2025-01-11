#include "tunnel.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"
#include "node.h"
#include "pipe_line.h"
#include "string.h" // memorySet
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

void insertTunnelToArray(tunnel_array_t *tc, tunnel_t *t)
{
    if (t->chain_index == kMaxChainLen)
    {
        LOGF("insertTunnelToArray overflow!");
        exit(1);
    }

    tc->tuns[tc->len++] = t;
}

void insertTunnelToChainInfo(tunnel_chain_info_t *tci, tunnel_t *t)
{
    insertTunnelToArray(&(tci->tunnels), t);
    tci->sum_padding_left += t->node->metadata.required_padding_left;
    tci->sum_padding_right += t->node->metadata.required_padding_right;
}

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
}

static void defaultUpStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnInitU(self->up, line);
}

static void defaultUpStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnEstU(self->up, line);
}

static void defaultUpStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnFinU(self->up, line);
}

static void defaultUpStreamPayload(tunnel_t *self, line_t *line, shift_buffer_t *payload)
{
    assert(self->up != NULL);
    self->up->fnPayloadU(self->up, line, payload);
}

static void defaultUpStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnPauseU(self->up, line);
}

static void defaultUpStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnResumeU(self->up, line);
}

static void defaultdownStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnInitD(self->up, line);
}

static void defaultdownStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnEstD(self->up, line);
}

static void defaultdownStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnFinD(self->up, line);
}

static void defaultdownStreamPayload(tunnel_t *self, line_t *line, shift_buffer_t *payload)
{
    assert(self->dw != NULL);
    self->up->fnPayloadD(self->up, line, payload);
}

static void defaultDownStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnPauseD(self->up, line);
}

static void defaultDownStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnResumeD(self->up, line);
}

static void defaultOnChain(tunnel_t *t, tunnel_chain_info_t *info)
{
    node_t *node = t->node;
    insertTunnelToChainInfo(info, t);

    if (node->hash_next == 0x0)
    {
        return;
    }

    node_t *next = getNode(node->node_manager_config, node->hash_next);

    if (next == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, next->name);
        exit(1);
    }

    assert(next->instance); // every node in node map is created byfore chaining

    tunnel_t *tnext = next->instance;
    chain(t, tnext);
    tnext->onChain(tnext, info);
}

static void defaultOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t index, uint16_t mem_offset)
{
    insertTunnelToArray(arr, t);
    t->chain_index   = index;
    t->cstate_offset = mem_offset;

    if (t->up)
    {
        t->up->onIndex(t->up, arr, index + 1, mem_offset + t->cstate_size);
    }
}

static void defaultOnChainingComplete(tunnel_t *t)
{
    (void)t;
}

static void defaultOnChainStart(tunnel_t *t)
{
    if (t->up)
    {
        t->up->onChainStart(t->up);
    }
}

tunnel_t *newTunnel(node_t *node, uint16_t tstate_size, uint16_t cstate_size)
{
    tunnel_t *ptr = memoryAllocate(sizeof(tunnel_t) + tstate_size);

    *ptr = (tunnel_t){.cstate_size = cstate_size,
                      .fnInitU     = &defaultUpStreamInit,
                      .fnInitD     = &defaultdownStreamInit,
                      .fnPayloadU  = &defaultUpStreamPayload,
                      .fnPayloadD  = &defaultdownStreamPayload,
                      .fnEstU      = &defaultUpStreamEst,
                      .fnEstD      = &defaultdownStreamEst,
                      .fnFinU      = &defaultUpStreamFin,
                      .fnFinD      = &defaultdownStreamFin,
                      .fnPauseU    = &defaultUpStreamPause,
                      .fnPauseD    = &defaultDownStreamPause,
                      .fnResumeU   = &defaultUpStreamResume,
                      .fnResumeD   = &defaultDownStreamResume,

                      .onChain            = &defaultOnChain,
                      .onIndex            = &defaultOnIndex,
                      .onChainingComplete = &defaultOnChainingComplete,
                      .onChainStart       = &defaultOnChainStart,

                      .node = node};

    return ptr;
}

pool_item_t *allocLinePoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return memoryAllocate(sizeof(line_t));
}

void destroyLinePoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    memoryFree(item);
}

pool_item_t *allocContextPoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return memoryAllocate(sizeof(context_t));
}

void destroyContextPoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    memoryFree(item);
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

static void defaultPipeLocalUpStream(tunnel_t *self, struct context_s *c, struct pipe_line_s *pl)
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

static void defaultPipeLocalDownStream(tunnel_t *self, struct context_s *c, struct pipe_line_s *pl)
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

// void pipeTo(tunnel_t *self, line_t *l, tid_t tid)
// {
//     assert(l->up_state == NULL);
//     newPipeLine(self, l, tid, defaultPipeLocalUpStream, defaultPipeLocalDownStream);
// }
