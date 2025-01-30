#include "tunnel.h"
#include "loggers/internal_logger.h"
#include "managers/node_manager.h"
#include "node.h"
#include "pipe_line.h"
#include "string.h" // memorySet

// `from` upstreams to `to`
void tunnelBindUp(tunnel_t *from, tunnel_t *to)
{
    from->up = to;
}

// `to` downstreams to `from`
void tunnelBindDown(tunnel_t *from, tunnel_t *to)
{
    // assert(to->dw == NULL); // 2 nodes cannot chain to 1 exact node
    // such chains are possible by a generic listener adapter
    // but the cyclic refrence detection is already done in node map
    to->dw = from;
}

// `from` <-> `to`
void tunnelBind(tunnel_t *from, tunnel_t *to)
{
    tunnelBindUp(from, to);
    tunnelBindDown(from, to);
}

void tunnelDefaultUpStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnInitU(self->up, line);
}

void tunnelDefaultUpStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnEstU(self->up, line);
}

void tunnelDefaultUpStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnFinU(self->up, line);
}

void tunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    assert(self->up != NULL);
    self->up->fnPayloadU(self->up, line, payload);
}

void tunnelDefaultUpStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnPauseU(self->up, line);
}

void tunnelDefaultUpStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->up != NULL);
    self->up->fnResumeU(self->up, line);
}

void tunnelDefaultdownStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnInitD(self->up, line);
}

void tunnelDefaultdownStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnEstD(self->up, line);
}

void tunnelDefaultdownStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnFinD(self->up, line);
}

void tunnelDefaultdownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    assert(self->dw != NULL);
    self->up->fnPayloadD(self->up, line, payload);
}

void tunnelDefaultDownStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnPauseD(self->up, line);
}

void tunnelDefaultDownStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->dw != NULL);
    self->up->fnResumeD(self->up, line);
}

void tunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc)
{
    node_t *node = tunnelGetNode(t);

    if (node->hash_next == 0x0)
    {
        tunnelchainInsert(tc, t);
        return;
    }

    node_t *next = nodemanagerGetNode(node->node_manager_config, node->hash_next);

    if (next == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, next->name);
        exit(1);
    }

    assert(next->instance); // every node in node map is created byfore chaining

    tunnel_t *tnext = next->instance;
    tunnelBind(t, tnext);

    assert(tnext->chain == NULL);
    tunnelchainInsert(tc, t);
    tnext->onChain(tnext, tc);
}

void tunnelDefaultOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset)
{
    tunnelarrayInesert(arr, t);
    t->chain_index   = *index;
    t->cstate_offset = *mem_offset;
    (*index)++;
    *mem_offset += t->lstate_size;
    if (t->up)
    {
        t->up->onIndex(t->up, arr, index, mem_offset);
    }
}

void tunnelDefaultOnPrepair(tunnel_t *t)
{
    (void) t;
}

void tunnelDefaultOnStart(tunnel_t *t)
{
    if (t->up)
    {
        t->up->onStart(t->up);
    }
}

enum
{
    kTunnelsMemSize = 16 * 200
};

tunnel_t *tunnelCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size)
{
    size_t tsize = sizeof(tunnel_t) + tstate_size;

    tunnel_t *ptr = memoryAllocate(sizeof(tunnel_t));

    memorySet(ptr, 0, tsize);

    *ptr = (tunnel_t){.lstate_size = lstate_size,
                      .fnInitU     = &tunnelDefaultUpStreamInit,
                      .fnInitD     = &tunnelDefaultdownStreamInit,
                      .fnPayloadU  = &tunnelDefaultUpStreamPayload,
                      .fnPayloadD  = &tunnelDefaultdownStreamPayload,
                      .fnEstU      = &tunnelDefaultUpStreamEst,
                      .fnEstD      = &tunnelDefaultdownStreamEst,
                      .fnFinU      = &tunnelDefaultUpStreamFin,
                      .fnFinD      = &tunnelDefaultdownStreamFin,
                      .fnPauseU    = &tunnelDefaultUpStreamPause,
                      .fnPauseD    = &tunnelDefaultDownStreamPause,
                      .fnResumeU   = &tunnelDefaultUpStreamResume,
                      .fnResumeD   = &tunnelDefaultDownStreamResume,
                      .onChain     = &tunnelDefaultOnChain,
                      .onIndex     = &tunnelDefaultOnIndex,
                      .onPrepair   = &tunnelDefaultOnPrepair,
                      .onStart     = &tunnelDefaultOnStart,
                      .node        = node};

    return ptr;
}

void tunnelDestroy(tunnel_t *self)
{
    memoryFree(self);
}

void pipeUpStream(context_t *c)
{
    if (! pipeSendToUpStream((pipe_line_t *) c->line->up_state, c))
    {
        if (c->payload)
        {
            contextReusePayload(c);
        }
        contextDestroy(c);
    }
}

void pipeDownStream(context_t *c)
{
    if (! pipeSendToDownStream((pipe_line_t *) c->line->dw_state, c))
    {
        if (c->payload)
        {
            contextReusePayload(c);
        }
        contextDestroy(c);
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
