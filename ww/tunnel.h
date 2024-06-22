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

// get the state object of each tunnel
#define STATE(x) ((void *) ((x)->state))

// get the line state at index I
#define LSTATE_I(x, y) ((void *) ((((x)->chains_state)[(y)])))
// mutate the line state at index I
#define LSTATE_I_MUT(x, y) (x)->chains_state[(y)]

// get the line state of current tunnel which is assumed to be named as `self`
#define LSTATE(x) LSTATE_I(x, self->chain_index)
// mutate the line state of current tunnel which is assumed to be named as `self`
#define LSTATE_MUT(x) LSTATE_I_MUT(x, self->chain_index)

// get the line state from the line of the context
#define CSTATE(x) LSTATE((x)->line)
// mutate the line state from the line of the context
#define CSTATE_MUT(x) LSTATE_MUT((x)->line)

/*
    While it is necessary to drop each state when line is closing,
    setting them to NULL can be removed on release build since the assert is also
    removed
*/
#if defined(RELEASE) && false
#define LSTATE_I_DROP(x, y)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        (void) (x);                                                                                                    \
        (void) (y);                                                                                                    \
    } while (0)
#else
#define LSTATE_I_DROP(x, y) (LSTATE_I_MUT((x), (y)) = NULL)
#endif

// mutate the state of line to NULL , this is done when the state is being freed and is necessary
#define LSTATE_DROP(x) LSTATE_I_DROP((x), self->chain_index)
// mutate the state of the line of context, this is done when the state is being freed and is necessary
#define CSTATE_DROP(x) LSTATE_DROP((x)->line)

typedef void (*LineFlowSignal)(void *state);

typedef uint32_t line_refc_t;

/*
    The line struct represnts a connection, it has to ends ( Down end < --------- > Up end)

    if forexample a write on the Downend blocks, it pauses the up end and wice wersa

    each context creation will increase refc on the line so, the line will never gets destroyed
    before the contexts that refrense it

    line holds all the info such as dest and src contexts, it also contains each tunnel per connection state
    in chains_state[(tunnel_index)]

    a line only belongs to 1 thread, but it can cross the threads (if actually needed) using pipe line, easily

*/

typedef struct line_s
{
    line_refc_t      refc;
    bool             alive;
    uint8_t          tid;
    bool             up_piped;
    bool             dw_piped;
    void            *up_state;
    void            *dw_state;
    LineFlowSignal   up_pause_cb;
    LineFlowSignal   up_resume_cb;
    LineFlowSignal   dw_pause_cb;
    LineFlowSignal   dw_resume_cb;
    socket_context_t src_ctx;
    socket_context_t dest_ctx;
    void            *chains_state[kMaxChainLen];
    uint8_t          auth_cur;

} line_t;

/*
    Context carries information, it belongs to the line it refrenses and prevent line destruction
    untill it gets destroyed

    and it can contain a payload buffer, or be just a flag context

    the only flag that also has a payload is `first` , other flags have no payload

*/
typedef struct context_s // 24
{
    shift_buffer_t *payload;
    line_t         *line;
    bool            init;
    bool            est;
    bool            first;
    bool            fin;
} context_t;

struct tunnel_s;

typedef void (*TunnelFlowRoutine)(struct tunnel_s *, struct context_s *);

/*
    Tunnel is just a doubly linked list, it has its own state, per connection state is stored in line structure
    which later gets accessed by the chain_index which is fixed

*/
typedef struct tunnel_s // 48
{
    void            *state;
    struct tunnel_s *dw, *up;

    TunnelFlowRoutine upStream;
    TunnelFlowRoutine downStream;

    uint8_t chain_index;
} tunnel_t;

tunnel_t *newTunnel(void);
void      destroyTunnel(tunnel_t *self);
void      chain(tunnel_t *from, tunnel_t *to);
void      chainDown(tunnel_t *from, tunnel_t *to);
void      chainUp(tunnel_t *from, tunnel_t *to);
void      defaultUpStream(tunnel_t *self, context_t *c);
void      defaultDownStream(tunnel_t *self, context_t *c);
void      pipeUpStream(context_t *c);
void      pipeDownStream(context_t *c);
void      pipeTo(tunnel_t *self, line_t *l, uint8_t tid);

// pool handles, instead of malloc / free  for the generic pool
pool_item_t *allocLinePoolHandle(struct generic_pool_s *pool);
void         destroyLinePoolHandle(struct generic_pool_s *pool, pool_item_t *item);

static inline line_t *newLine(uint8_t tid)
{
    line_t *result = popPoolItem(line_pools[tid]);

    *result = (line_t){
        .tid          = tid,
        .refc         = 1,
        .auth_cur     = 0,
        .alive        = true,
        .chains_state = {0},
        // to set a port we need to know the AF family, default v4
        .dest_ctx = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}},
        .src_ctx  = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}},
    };

    return result;
}

static inline bool isAlive(line_t *line)
{
    return line->alive;
}

/*
    Once the up state is setup, it will receive pasue/resume events from down end of the line, with the `state` as
   userdata
*/
static inline void setupLineUpSide(line_t *l, LineFlowSignal pause_cb, void *state, LineFlowSignal resume_cb)
{
    assert(l->up_state == NULL || l->up_pause_cb == NULL);
    l->up_state     = state;
    l->up_pause_cb  = pause_cb;
    l->up_resume_cb = resume_cb;
}

/*
    Once the down state is setup, it will receive pasue/resume events from up end of the line, with the `state` as
   userdata
*/
static inline void setupLineDownSide(line_t *l, LineFlowSignal pause_cb, void *state, LineFlowSignal resume_cb)
{
    assert(l->dw_state == NULL || l->dw_pause_cb == NULL);
    l->dw_state     = state;
    l->dw_pause_cb  = pause_cb;
    l->dw_resume_cb = resume_cb;
}

static inline void doneLineUpSide(line_t *l)
{
    assert(l->up_state != NULL || l->up_pause_cb == NULL);
    l->up_state = NULL;
}

static inline void doneLineDownSide(line_t *l)
{
    assert(l->dw_state != NULL || l->dw_pause_cb == NULL);
    l->dw_state = NULL;
}

static inline void pauseLineUpSide(line_t *l)
{
    if (l->up_state)
    {
        l->up_pause_cb(l->up_state);
    }
}

static inline void pauseLineDownSide(line_t *l)
{
    if (l->dw_state)
    {
        l->dw_pause_cb(l->dw_state);
    }
}

static inline void resumeLineUpSide(line_t *l)
{
    if (l->up_state)
    {
        l->up_resume_cb(l->up_state);
    }
}

static inline void resumeLineDownSide(line_t *l)
{
    if (l->dw_state)
    {
        l->dw_resume_cb(l->dw_state);
    }
}

/*
    called from unlockline which mostly is because destroy context
*/
static inline void internalUnRefLine(line_t *l)
{
    if (--(l->refc) > 0)
    {
        return;
    }

    assert(l->alive == false);

    // there should not be any conn-state alive at this point
    for (size_t i = 0; i < kMaxChainLen; i++)
    {
        assert(LSTATE_I(l, i) == NULL);
    }
    assert(l->up_state == NULL);
    assert(l->dw_state == NULL);

    // assert(l->src_ctx.domain == NULL); // impossible (source domain?) (no need to assert)

    if (l->dest_ctx.domain != NULL && ! l->dest_ctx.domain_constant)
    {
        free(l->dest_ctx.domain);
    }

    reusePoolItem(line_pools[l->tid], l);
}

/*
    called mostly because create context
*/
static inline void lockLine(line_t *line)
{
    assert(line->alive || line->refc > 0);
    // basic overflow protection
    assert(line->refc < (((0x1ULL << ((sizeof(line->refc) * 8ULL) - 1ULL)) - 1ULL) |
                         (0xFULL << ((sizeof(line->refc) * 8ULL) - 4ULL))));
    line->refc++;
}

static inline void unLockLine(line_t *line)
{
    internalUnRefLine(line);
}

/*
    Only the line creator must call this when it wants to end the line, this dose net necessarily free the context
   instantly, but it will be freed as soon as the refc becomes zero which means no context is alive for this line, and
   the line can still be used regularly during the time that it has at least 1 ref

*/
static inline void destroyLine(line_t *l)
{
    l->alive = false;
    unLockLine(l);
}
// pool handles, instead of malloc / free  for the generic pool
pool_item_t *allocContextPoolHandle(struct generic_pool_s *pool);
void         destroyContextPoolHandle(struct generic_pool_s *pool, pool_item_t *item);

static inline void destroyContext(context_t *c)
{
    assert(c->payload == NULL);
    const uint8_t tid = c->line->tid;
    unLockLine(c->line);
    reusePoolItem(context_pools[tid], c);
}

static inline context_t *newContext(line_t *line)
{
    context_t *new_ctx = popPoolItem(context_pools[line->tid]);
    *new_ctx           = (context_t){.line = line};
    lockLine(line);
    return new_ctx;
}

static inline context_t *newContextFrom(context_t *source)
{
    lockLine(source->line);
    context_t *new_ctx = popPoolItem(context_pools[source->line->tid]);
    *new_ctx           = (context_t){.line = source->line};
    return new_ctx;
}

static inline context_t *newEstContext(line_t *line)
{
    context_t *c = newContext(line);
    c->est       = true;
    return c;
}

static inline context_t *newFinContext(line_t *l)
{
    context_t *c = newContext(l);
    c->fin       = true;
    return c;
}

static inline context_t *newFinContextFrom(context_t *source)
{
    context_t *c = newContextFrom(source);
    c->fin       = true;
    return c;
}

static inline context_t *newInitContext(line_t *line)
{
    context_t *c = newContext(line);
    c->init      = true;
    return c;
}

static inline context_t *switchLine(context_t *c, line_t *line)
{
    lockLine(line);
    unLockLine(c->line);
    c->line = line;
    return c;
}

static inline void markAuthenticated(line_t *line)
{
    line->auth_cur += 1;
}

static inline bool isAuthenticated(line_t *line)
{
    return line->auth_cur > 0;
}

static inline buffer_pool_t *getThreadBufferPool(uint8_t tid)
{
    return buffer_pools[tid];
}

static inline buffer_pool_t *getLineBufferPool(line_t *l)
{
    return buffer_pools[l->tid];
}

static inline buffer_pool_t *getContextBufferPool(context_t *c)
{
    return buffer_pools[c->line->tid];
}

static inline void reuseContextBuffer(context_t *c)
{
    assert(c->payload != NULL);
    reuseBuffer(getContextBufferPool(c), c->payload);
    c->payload = NULL;
}

static inline bool isUpPiped(line_t *l)
{
    return l->up_piped;
}

static inline bool isDownPiped(line_t *l)
{
    return l->dw_piped;
}

static inline hloop_t *getLineLoop(line_t *l)
{
    return loops[l->tid];
}
