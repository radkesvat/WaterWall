#pragma once
#include "wlibc.h"
#include "buffer_pool.h"
#include "generic_pool.h"
#include "hloop.h"
#include "socket_context.h"

#include "node.h"
#include "shiftbuffer.h"
#include "worker.h"

/*
    Tunnels basicly encapsulate / decapsulate the packets and pass it to the next tunnel.
    something like this:

    ------------------------------ chain ---------------------------------

      --------------            --------------            --------------
      |            | ---------> |            | ---------> |            |
      |  Tunnel 1  |            |  Tunnel 2  |            |  Tunnel 3  |
      |            | <--------- |            | <--------- |            |
      --------------            --------------            --------------

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
    kMaxChainLen = (16 * 4)
};

// get the state object of each tunnel
#define TSTATE(x) ((void *) ((x)->state))

// get the line state at index I
#define LSTATE_I(x, y) ((void *) ((((x)->chains_state)[(y)])))
// mutate the line state at index I
#define LSTATE_I_MUT(x, y) (x)->chains_state[(y)]

// get the line state by using the chain_index of current tunnel which is assumed to be named as `self`
#define LSTATE(x) LSTATE_I(x, self->chain_index)
// mutate the line state by using the chain_index of current tunnel which is assumed to be named as `self`
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
#if defined(RELEASE)
#define LSTATE_I_DROP(x, y)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        (void) (x);                                                                                                    \
        (void) (y);                                                                                                    \
    } while (0)
#else
#define LSTATE_I_DROP(x, y) (LSTATE_I_MUT((x), (y)) = NULL)
#endif

// mutate the state of line (at the index of current tunnel which is assumed to be named as `self`) to NULL
// this is done when the state is being freed and is necessary
#define LSTATE_DROP(x) LSTATE_I_DROP((x), self->chain_index)
// mutate the state of the line of context to NULL
#define CSTATE_DROP(x) LSTATE_DROP((x)->line)

typedef void (*LineFlowSignal)(void *state);

typedef uint32_t line_refc_t;



typedef struct pipeline_s
{
    atomic_bool closed;
    atomic_uint pipeline_refc;
    // compiler will insert padding here
    struct line_s *up;
    struct line_s *dw;
} pipe_line_t;

/*
    The line struct represents a connection, it has two ends ( Down-end < --------- > Up-end)

    if forexample a write on the Down-end blocks, it pauses the Up-end and wice wersa

    each context creation will increase refc on the line, so the line will never gets destroyed
    before the contexts that refrense it

    line holds all the info such as dest and src contexts, it also contains each tunnel per connection state
    in chains_state[(tunnel_index)]

    a line only belongs to 1 thread, but it can cross the threads (if actually needed) using pipe line, easily

*/

typedef struct line_s
{
    line_refc_t refc;
    tid_t       tid;

    bool    alive;
    uint8_t auth_cur;

    socket_context_t src_ctx;
    socket_context_t dest_ctx;
    pipe_line_t     *pipe;

    uintptr_t *chains_state[] __attribute__((aligned(sizeof(void *))));

} line_t;

/*
    Context carries information, it belongs to the line it refrenses and prevent line destruction
    untill it gets destroyed

    and it can contain a payload buffer, or be just a flag context

*/
typedef struct context_s
{
    shift_buffer_t *payload;
    line_t         *line;
    bool            init;
    bool            est;
    bool            fin;
} context_t;

typedef enum
{
    kSCBlocked,
    kSCRequiredBytes,
    kSCSuccessNoData,
    kSCSuccess
} splice_retcode_t;

struct tunnel_s;
typedef struct tunnel_s tunnel_t;

typedef struct tunnel_array_t
{
    uint16_t  len;
    tunnel_t *tuns[kMaxChainLen];

} tunnel_array_t;

typedef struct tunnel_chain_info_s
{

    uint16_t       sum_padding_left;
    uint16_t       sum_padding_right;
    tunnel_array_t tunnels;

} tunnel_chain_info_t;

typedef void (*TunnelStatusCb)(tunnel_t *);
typedef void (*TunnelChainFn)(tunnel_t *, tunnel_chain_info_t *info);
typedef void (*TunnelIndexFn)(tunnel_t *, tunnel_array_t *arr, uint16_t index, uint16_t mem_offset);
typedef void (*TunnelFlowRoutineInit)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePayload)(tunnel_t *, line_t *line, shift_buffer_t *payload);
typedef void (*TunnelFlowRoutineEst)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineFin)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePause)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineResume)(tunnel_t *, line_t *line);
typedef splice_retcode_t (*TunnelFlowRoutineSplice)(tunnel_t *, line_t *line, int pipe_fd, size_t len);

/*
    Tunnel is just a doubly linked list, it has its own state, per connection state is stored in line structure
    which later gets accessed by the chain_index which is fixed

    node(Create) -> onChain -> onChainingComplete -> onIndex -> onChainStart -> node(Destroy)

*/
struct tunnel_s
{
    tunnel_t *up, *dw;

    // TunnelFlowRoutine upStream;
    // TunnelFlowRoutine downStream;

    TunnelFlowRoutineInit    fnInitU;
    TunnelFlowRoutineInit    fnInitD;
    TunnelFlowRoutinePayload fnPayloadU;
    TunnelFlowRoutinePayload fnPayloadD;
    TunnelFlowRoutineEst     fnEstU;
    TunnelFlowRoutineEst     fnEstD;
    TunnelFlowRoutineFin     fnFinU;
    TunnelFlowRoutineFin     fnFinD;
    TunnelFlowRoutinePause   fnPauseU;
    TunnelFlowRoutinePause   fnPauseD;
    TunnelFlowRoutineResume  fnResumeU;
    TunnelFlowRoutineResume  fnResumeD;

    TunnelChainFn  onChain;
    TunnelIndexFn  onIndex;
    TunnelStatusCb onChainingComplete;
    TunnelStatusCb onChainStart;

    uint16_t tstate_size;
    uint16_t cstate_size;

    uint16_t cstate_offset;
    uint16_t chain_index;

    struct node_s *node;

    bool chain_head;

    uint8_t state[] __attribute__((aligned(sizeof(void *))));
};

tunnel_t *newTunnel(struct node_s *node, uint16_t tstate_size, uint16_t cstate_size);
void      destroyTunnel(tunnel_t *self);
void      chain(tunnel_t *from, tunnel_t *to);
void      chainDown(tunnel_t *from, tunnel_t *to);
void      chainUp(tunnel_t *from, tunnel_t *to);

void insertTunnelToArray(tunnel_array_t *tc, tunnel_t *t);
void insertTunnelToChainInfo(tunnel_chain_info_t *tci, tunnel_t *t);

static inline void setTunnelState(tunnel_t *self, void *state)
{
    memcpy(&(self->state[0]), state, self->tstate_size);
}

// pool handles, instead of malloc / free for the generic pool
pool_item_t *allocLinePoolHandle(struct generic_pool_s *pool);
void         destroyLinePoolHandle(struct generic_pool_s *pool, pool_item_t *item);

static inline line_t *newLine(tid_t tid)
{
    line_t *result = popPoolItem(getWorkerLinePool(tid));

    *result =
        (line_t){.tid          = tid,
                 .refc         = 1,
                 .auth_cur     = 0,
                 .alive        = true,
                 .chains_state = {0},
                 // to set a port we need to know the AF family, default v4
                 .dest_ctx = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}},
                 .src_ctx  = (socket_context_t){.address.sa = (struct sockaddr){.sa_family = AF_INET, .sa_data = {0}}}};

    return result;
}

static inline bool isAlive(const line_t *const line)
{
    return line->alive;
}

/*
    Once the up state is setup, it will receive pasue/resume events from down end of the line, with the `state` as
   userdata
*/
// static inline void setupLineUpSide(line_t *const l, LineFlowSignal pause_cb, void *const state,
//                                    LineFlowSignal resume_cb)
// {
//     assert(l->up_state == NULL);
//     l->up_state     = state;
//     l->up_pause_cb  = pause_cb;
//     l->up_resume_cb = resume_cb;
// }

/*
    Once the down state is setup, it will receive pasue/resume events from up end of the line, with the `state` as
   userdata
*/
// static inline void setupLineDownSide(line_t *const l, LineFlowSignal pause_cb, void *const state,
//                                      LineFlowSignal resume_cb)
// {
//     assert(l->dw_state == NULL);
//     l->dw_state     = state;
//     l->dw_pause_cb  = pause_cb;
//     l->dw_resume_cb = resume_cb;
// }

// static inline void doneLineUpSide(line_t *const l)
// {
//     assert(l->up_state != NULL || l->up_pause_cb == NULL);
//     l->up_state = NULL;
// }

// static inline void doneLineDownSide(line_t *const l)
// {
//     assert(l->dw_state != NULL || l->dw_pause_cb == NULL);
//     l->dw_state = NULL;
// }

// static inline void pauseLineUpSide(line_t *const l)
// {
//     if (l->up_state)
//     {
//         l->up_pause_cb(l->up_state);
//     }
// }

// static inline void pauseLineDownSide(line_t *const l)
// {
//     if (l->dw_state)
//     {
//         l->dw_pause_cb(l->dw_state);
//     }
// }

// static inline void resumeLineUpSide(line_t *const l)
// {
//     if (l->up_state)
//     {
//         l->up_resume_cb(l->up_state);
//     }
// }

// static inline void resumeLineDownSide(line_t *const l)
// {
//     if (l->dw_state)
//     {
//         l->dw_resume_cb(l->dw_state);
//     }
// }

/*
    called from unlockline which mostly is because destroy context
*/
static inline void internalUnRefLine(line_t *const l)
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
    // assert(l->up_state == NULL);
    // assert(l->dw_state == NULL);

    // assert(l->src_ctx.domain == NULL); // impossible (source domain?) (no need to assert)

    if (l->dest_ctx.domain != NULL && ! l->dest_ctx.domain_constant)
    {
        memoryFree(l->dest_ctx.domain);
    }

    reusePoolItem(getWorkerLinePool(l->tid), l);
}

/*
    called mostly because create context
*/
static inline void lockLine(line_t *const line)
{
    assert(line->alive || line->refc > 0);
    // basic overflow protection
    assert(line->refc < (((0x1ULL << ((sizeof(line->refc) * 8ULL) - 1ULL)) - 1ULL) |
                         (0xFULL << ((sizeof(line->refc) * 8ULL) - 4ULL))));
    line->refc++;
}

static inline void unLockLine(line_t *const line)
{
    internalUnRefLine(line);
}

/*
    Only the line creator must call this when it wants to end the line, this dose not necessarily free the line
   instantly, but it will be freed as soon as the refc becomes zero which means no context is alive for this line, and
   the line can still be used regularly during the time that it has at least 1 ref

*/
static inline void destroyLine(line_t *const l)
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
    const tid_t tid = c->line->tid;
    unLockLine(c->line);
    reusePoolItem(getWorkerContextPool(tid), c);
}

static inline context_t *newContext(line_t *const line)
{
    context_t *new_ctx = popPoolItem(getWorkerContextPool(line->tid));
    *new_ctx           = (context_t){.line = line};
    lockLine(line);
    return new_ctx;
}

static inline context_t *newContextFrom(const context_t *const source)
{
    lockLine(source->line);
    context_t *new_ctx = popPoolItem(getWorkerContextPool(source->line->tid));
    *new_ctx           = (context_t){.line = source->line};
    return new_ctx;
}

static inline context_t *newEstContext(line_t *const line)
{
    context_t *c = newContext(line);
    c->est       = true;
    return c;
}

static inline context_t *newFinContext(line_t *const l)
{
    context_t *c = newContext(l);
    c->fin       = true;
    return c;
}

static inline context_t *newFinContextFrom(context_t *const source)
{
    context_t *c = newContextFrom(source);
    c->fin       = true;
    return c;
}

static inline context_t *newInitContext(line_t *const line)
{
    context_t *c = newContext(line);
    c->init      = true;
    return c;
}

static inline context_t *switchLine(context_t *const c, line_t *const line)
{
    lockLine(line);
    unLockLine(c->line);
    c->line = line;
    return c;
}

static inline void markAuthenticated(line_t *const line)
{
    // basic overflow protection
    assert(line->auth_cur < (((0x1ULL << ((sizeof(line->auth_cur) * 8ULL) - 1ULL)) - 1ULL) |
                             (0xFULL << ((sizeof(line->auth_cur) * 8ULL) - 4ULL))));
    line->auth_cur += 1;
}

static inline bool isAuthenticated(line_t *const line)
{
    return line->auth_cur > 0;
}

static inline buffer_pool_t *getLineBufferPool(const line_t *const l)
{
    return getWorkerBufferPool(l->tid);
}

static inline buffer_pool_t *getContextBufferPool(const context_t *const c)
{
    return getWorkerBufferPool(c->line->tid);
}

/*
    same as c->payload = NULL, this is necessary before destroying a context to prevent bugs, dose nothing on release
    build
*/

static inline void dropContexPayload(context_t *const c)
{
#if defined(RELEASE)
    (void) (c);
#else
    assert(c->payload != NULL);
    c->payload = NULL;
#endif
}

static inline void reuseContextPayload(context_t *const c)
{
    assert(c->payload != NULL);
    reuseBuffer(getContextBufferPool(c), c->payload);
    dropContexPayload(c);
}

static inline bool isUpPiped(const line_t *const l)
{
    return l->pipe != NULL && l->pipe->up != NULL;
}

static inline bool isDownPiped(const line_t *const l)
{
    return l->pipe != NULL && l->pipe->dw != NULL;
}

static inline hloop_t *getLineLoop(const line_t *const l)
{
    return getWorkerLoop(l->tid);
}
