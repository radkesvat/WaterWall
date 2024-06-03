#pragma once

#include "basic_types.h"
#include "buffer_pool.h"
#include "generic_pool.h"
#include "hloop.h"
#include "shiftbuffer.h"
#include "ww.h"

/*
    Tunnels basicly encapsulate / decapsulate the packets and pass it to the next tunnel.
    something like this:

    ----------------------------- a chain -------------------------------

    ---------------            ---------------            ---------------
    |             | ---------> |             | ---------> |             |
    |  Tunnel 1   |            |  Tunnel 2   |            |  Tunnel 3   |
    |             | <--------- |             | <--------- |             |
    ---------------            ---------------            ---------------

    ----------------------------------------------------------------------

    Tunnel 1 and 3 are also called adapters since they have a os socket to read and write to

    Nodes are mostly pairs, means that 1 pair is the client (imagine a node that encrypts data)
    and other node is the server (imagine a node that decrypts data)

    We don't care what a node is doing with packets
    as long as it provides a upstream and downstream function its a node that can join the chain

    And each tunnel knows that every connection can belong to any thread
    so we created everything threadlocal, such as buffer pools, eventloops, etc...

*/

enum
{
    kMaxChainLen = (16 * 2)
};

#define STATE(x) ((void *) ((x)->state))

#define LSTATE_I(x, y)     ((void *) ((((x)->chains_state)[y])))
#define LSTATE_I_MUT(x, y) (x)->chains_state[y]

#define LSTATE(x)     LSTATE_I(x, self->chain_index)
#define LSTATE_MUT(x) LSTATE_I_MUT(x, self->chain_index)

#define CSTATE(x)     LSTATE((x)->line)
#define CSTATE_MUT(x) LSTATE_MUT((x)->line)

typedef void (*LineFlowSignal)(void *state);

typedef struct line_s
{
    hloop_t         *loop;
    void            *chains_state[kMaxChainLen];
    void            *up_state;
    void            *dw_state;
    LineFlowSignal   up_pause_cb;
    LineFlowSignal   up_resume_cb;
    LineFlowSignal   dw_pause_cb;
    LineFlowSignal   dw_resume_cb;
    uint16_t         refc;
    uint8_t          tid;
    uint8_t          lcid;
    uint8_t          auth_cur;
    bool             alive;
    socket_context_t src_ctx;
    socket_context_t dest_ctx;

} line_t;

typedef struct context_s
{
    line_t         *line;
    shift_buffer_t *payload;
    bool            init;
    bool            est;
    bool            first;
    bool            fin;
} context_t;

struct tunnel_s;

typedef void (*TunnelFlowRoutine)(struct tunnel_s *, struct context_s *);

struct tunnel_s
{
    void            *state;
    struct tunnel_s *dw, *up;

    TunnelFlowRoutine upStream;
    TunnelFlowRoutine downStream;

    uint8_t chain_index;
};

typedef struct tunnel_s tunnel_t;

tunnel_t *newTunnel(void);
void      destroyTunnel(tunnel_t *self);
void      chain(tunnel_t *from, tunnel_t *to);
void      chainDown(tunnel_t *from, tunnel_t *to);
void      chainUp(tunnel_t *from, tunnel_t *to);
void      defaultUpStream(tunnel_t *self, context_t *c);
void      defaultDownStream(tunnel_t *self, context_t *c);

pool_item_t *allocLinePoolHandle(struct generic_pool_s *pool);
void         destroyLinePoolHandle(struct generic_pool_s *pool, pool_item_t *item);

inline line_t *newLine(uint8_t tid)
{
    line_t *result = popPoolItem(line_pools[tid]);

    *result = (line_t){
        .tid          = tid,
        .refc         = 1,
        .lcid         = kMaxChainLen - 1,
        .auth_cur     = 0,
        .loop         = loops[tid],
        .alive        = true,
        .chains_state = {0},
        // to set a port we need to know the AF family, default v4
        .dest_ctx = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}},
        .src_ctx  = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}},
    };

    return result;
}

inline bool isAlive(line_t *line)
{
    return line->alive;
}

inline void setupLineUpSide(line_t *l, LineFlowSignal pause_cb, void *state, LineFlowSignal resume_cb)
{
    l->up_state     = state;
    l->up_pause_cb  = pause_cb;
    l->up_resume_cb = resume_cb;
}

inline void setupLineDownSide(line_t *l, LineFlowSignal pause_cb, void *state, LineFlowSignal resume_cb)
{
    l->dw_state     = state;
    l->dw_pause_cb  = pause_cb;
    l->dw_resume_cb = resume_cb;
}

inline void doneLineUpSide(line_t *l)
{
    l->up_state = NULL;
}

inline void doneLineDownSide(line_t *l)
{
    l->dw_state = NULL;
}

inline void pauseLineUpSide(line_t *l)
{
    if (l->up_state)
    {
        l->up_pause_cb(l->up_state);
    }
}

inline void pauseLineDownSide(line_t *l)
{
    if (l->dw_state)
    {
        l->dw_pause_cb(l->dw_state);
    }
}

inline void resumeLineUpSide(line_t *l)
{
    if (l->up_state)
    {
        l->up_resume_cb(l->up_state);
    }
}

inline void resumeLineDownSide(line_t *l)
{
    if (l->dw_state)
    {
        l->dw_resume_cb(l->dw_state);
    }
}

inline uint8_t reserveChainStateIndex(line_t *l)
{
    uint8_t result = l->lcid;
    l->lcid -= 1;
    return result;
}

inline void internalUnRefLine(line_t *l)
{
    l->refc -= 1;
    // check line
    if (l->refc > 0)
    {
        return;
    }

    assert(l->alive == false);

    // there should not be any conn-state alive at this point
    for (size_t i = 0; i < kMaxChainLen; i++)
    {
        assert(l->chains_state[i] == NULL);
    }

    assert(l->src_ctx.domain == NULL); // impossible (source domain?)

    if (l->dest_ctx.domain != NULL && ! l->dest_ctx.domain_constant)
    {
        free(l->dest_ctx.domain);
    }

    reusePoolItem(line_pools[l->tid], l);
}

inline void lockLine(line_t *line)
{
    line->refc++;
}

inline void unLockLine(line_t *line)
{
    internalUnRefLine(line);
}

inline void destroyLine(line_t *l)
{
    l->alive = false;
    unLockLine(l);
}

pool_item_t *allocContextPoolHandle(struct generic_pool_s *pool);
void         destroyContextPoolHandle(struct generic_pool_s *pool, pool_item_t *item);

inline void destroyContext(context_t *c)
{
    assert(c->payload == NULL);
    const uint8_t tid = c->line->tid;
    unLockLine(c->line);
    reusePoolItem(context_pools[tid], c);
}

inline context_t *newContext(line_t *line)
{
    context_t *new_ctx = popPoolItem(context_pools[line->tid]);
    *new_ctx           = (context_t){.line = line};
    lockLine(line);
    return new_ctx;
}

inline context_t *newContextFrom(context_t *source)
{
    lockLine(source->line);
    context_t *new_ctx = popPoolItem(context_pools[source->line->tid]);
    *new_ctx           = (context_t){.line = source->line};
    return new_ctx;
}

inline context_t *newEstContext(line_t *line)
{
    context_t *c = newContext(line);
    c->est       = true;
    return c;
}

inline context_t *newFinContext(line_t *l)
{
    context_t *c = newContext(l);
    c->fin       = true;
    return c;
}

inline context_t *newFinContextFrom(context_t *source)
{
    context_t *c = newContextFrom(source);
    c->fin       = true;
    return c;
}

inline context_t *newInitContext(line_t *line)
{
    context_t *c = newContext(line);
    c->init      = true;
    return c;
}

inline context_t *switchLine(context_t *c, line_t *line)
{
    lockLine(line);
    unLockLine(c->line);
    c->line = line;
    return c;
}

inline void markAuthenticated(line_t *line)
{
    line->auth_cur += 1;
}

inline bool isAuthenticated(line_t *line)
{
    return line->auth_cur > 0;
}

inline buffer_pool_t *getThreadBufferPool(uint8_t tid)
{
    return buffer_pools[tid];
}

inline buffer_pool_t *getLineBufferPool(line_t *l)
{
    return buffer_pools[l->tid];
}

inline buffer_pool_t *getContextBufferPool(context_t *c)
{
    return buffer_pools[c->line->tid];
}

inline void reuseContextBuffer(context_t *c)
{
    assert(c->payload != NULL);
    reuseBuffer(getContextBufferPool(c), c->payload);
    c->payload = NULL;
}
