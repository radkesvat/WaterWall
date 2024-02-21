#pragma once

#include "basic_types.h"
#include "hv/hatomic.h"
#include "hv/hloop.h"
#include "shiftbuffer.h"

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
        reuseBuffer(buffer_pools[x->line->tid], x->payload); \
        x->payload = NULL;                                   \
    } while (0)

typedef struct line_s
{
    hloop_t *loop;
    socket_context_t dest_ctx;
    socket_context_t src_ctx;
    uint16_t id;
    size_t tid;
    void *chains_state[];

} line_t;

typedef struct context_s
{
    hio_t *src_io;
    line_t *line;
    shift_buffer_t *payload;

    //--------------
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

line_t *newLine(size_t tid);
void destroyLine(line_t *con);

context_t *newContext(line_t *line);
void destroyContext(context_t *c);

void destroyTunnel(tunnel_t *self);
void chain(tunnel_t *self, tunnel_t *next);
void destroyChain(tunnel_t *self);

void defaultUpStream(tunnel_t *self, context_t *c);
void defaultPacketUpStream(tunnel_t *self, context_t *c);
void defaultDownStream(tunnel_t *self, context_t *c);
void defaultPacketDownStream(tunnel_t *self, context_t *c);
