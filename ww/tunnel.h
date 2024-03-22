#pragma once

#include "basic_types.h"
#include "hv/hatomic.h"
#include "hv/hloop.h"
#include "buffer_pool.h"

#define MAX_CHAIN_LEN 50
#define MAX_WAITERS 20

#ifdef DEBUG
#define NEXT_STATE(x) (x->cur++)
#elif NDEBUG
#define NEXT_STATE(x)                    \
    do                                   \
    {                                    \
        (x->cur++);                      \
        assert(cx->cur < MAX_CHAIN_LEN); \
    } while (0)
#endif

#ifdef DEBUG
#define PREV_STATE(x) (x->cur--)
#elif NDEBUG
#define PREV_STATE(x)         \
    do                        \
    {                         \
        (x->cur--);           \
        assert(cx->cur >= 0); \
    } while (0)
#endif

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
    uint16_t id;
    size_t tid;
    size_t refc;
    void *chains_state[];

} line_t;

typedef struct context_s
{
    hio_t *src_io;
    line_t *line;
    shift_buffer_t *payload;
    socket_context_t dest_ctx;

    //--------------
    uint16_t packet_size; // used for packet based protocols
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
inline line_t *newLine(size_t tid)
{
    size_t size = sizeof(line_t) + (sizeof(void *) * MAX_CHAIN_LEN);
    line_t *result = malloc(size);
    memset(result, 0, size);
    result->tid = tid;
    result->refc = 1;
    result->loop = loops[tid];
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

    free(l);
}
inline void destroyContext(context_t *c)
{
    assert(c->payload == NULL);
    if (c->dest_ctx.domain != NULL)
        free(c->dest_ctx.domain);
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
inline context_t *copyContext(context_t *c)
{
    c->line->refc += 1;
    context_t *new_ctx = malloc(sizeof(context_t));
    *new_ctx = *c;
    c->dest_ctx.domain = NULL; // only move

    return new_ctx;
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
    destroyLine(c->line);
    line->refc += 1;
    c->line = line;
    return c;
}