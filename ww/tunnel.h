#pragma once

#include "basic_types.h"
#include "hv/hatomic.h"
#include "hv/hloop.h"
#include "buffer_pool.h"

#define MAX_CHAIN_LEN 50


#define DISCARD_CONTEXT(x)                                   \
    do                                                       \
    {                                                        \
        assert(x->payload != NULL);                          \
        reuseBuffer(buffer_pools[x->line->tid], x->payload); \
        x->payload = NULL;                                   \
    } while (0)

typedef struct line_s
{
    hloop_t *loop;
    socket_context_t src_ctx;
    socket_context_t dest_ctx;

    uint16_t tid;
    uint16_t refc;
    uint16_t lcid;
    void *chains_state[];

} line_t;

typedef struct context_s
{
    hio_t *src_io;
    line_t *line;
    shift_buffer_t *payload;

    bool init;
    bool est;
    bool first;
    bool fin;
} context_t;

typedef struct tunnel_s
{
    void *state;
    hloop_t **loops;
    struct tunnel_s *dw, *up;

    void (*upStream)(struct tunnel_s *self, context_t *c);
    void (*packetUpStream)(struct tunnel_s *self, context_t *c);
    void (*downStream)(struct tunnel_s *self, context_t *c);
    void (*packetDownStream)(struct tunnel_s *self, context_t *c);

    size_t chain_index;

} tunnel_t;

tunnel_t *newTunnel();

void destroyTunnel(tunnel_t *self);
void chain(tunnel_t *self, tunnel_t *next);
void defaultUpStream(tunnel_t *self, context_t *c);
void defaultPacketUpStream(tunnel_t *self, context_t *c);
void defaultDownStream(tunnel_t *self, context_t *c);
void defaultPacketDownStream(tunnel_t *self, context_t *c);

extern struct hloop_s **loops; // ww.h runtime api
inline line_t *newLine(uint16_t tid)
{
    size_t size = sizeof(line_t) + (sizeof(void *) * MAX_CHAIN_LEN);
    line_t *result = malloc(size);
    memset(result, 0, size);
    result->tid = tid;
    result->refc = 1;
    result->lcid = MAX_CHAIN_LEN - 1;
    result->loop = loops[tid];
    result->loop = loops[tid];
    result->dest_ctx.addr.sa.sa_family = AF_INET;
    result->src_ctx.addr.sa.sa_family = AF_INET;
    return result;
}
inline size_t reserveChainStateIndex(line_t *l){
    size_t result = l->lcid;
    l->lcid -=1;
    return result;
}
inline void destroyLine(line_t *l)
{
    l->refc -= 1;
    // check line
    if (l->refc > 0)
        return;

#ifdef DEBUG
    // there should not be any conn-state alive at this point
    for (size_t i = 0; i < MAX_CHAIN_LEN; i++)
    {
        assert(l->chains_state[i] == NULL);
    }
#endif
    if (l->dest_ctx.domain != NULL)
        free(l->dest_ctx.domain);
    free(l);
}
inline void destroyContext(context_t *c)
{
    assert(c->payload == NULL);

    destroyLine(c->line);

    free(c);
}
inline context_t *newContext(line_t *line)
{
    context_t *new_ctx = malloc(sizeof(context_t));
    memset(new_ctx, 0, sizeof(context_t));
    new_ctx->line = line;
    line->refc += 1;
    return new_ctx;
}

inline context_t *newContextFrom(context_t *source)
{
    source->line->refc += 1;
    context_t *new_ctx = malloc(sizeof(context_t));
    *new_ctx = *source;
    new_ctx->payload = NULL;
    new_ctx->init = false;
    new_ctx->est = false;
    new_ctx->first = false;
    new_ctx->fin = false;
    return new_ctx;
}
inline context_t *newEstContext(line_t *line)
{
    context_t *c = newContext(line);
    c->est = true;
    return c;
}

inline context_t *newFinContext(line_t *line)
{
    context_t *c = newContext(line);
    c->fin = true;
    return c;
}

inline context_t *newInitContext(line_t *line)
{
    context_t *c = newContext(line);
    c->init = true;
    return c;
}
inline context_t *switchLine(context_t *c, line_t *line)
{
    line->refc += 1;
    destroyLine(c->line);
    c->line = line;
    return c;
}