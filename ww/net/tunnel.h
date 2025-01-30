#pragma once
#include "buffer_pool.h"
#include "generic_pool.h"
#include "connection_context.h"
#include "wlibc.h"
#include "wloop.h"

#include "chain.h"
#include "context.h"
#include "line.h"
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

// get the state object of each tunnel
#define TSTATE(x) ((void *) ((x)->state))

// get the line state at index I
#define LSTATE_I(x, y) ((void *) ((((x)->tunnels_line_state)[(y)])))
// mutate the line state at index I
#define LSTATE_I_MUT(x, y) (x)->tunnels_line_state[(y)]

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

typedef struct node_s         node_t;
typedef struct tunnel_s       tunnel_t;
typedef struct tunnel_chain_s tunnel_chain_t;
typedef struct tunnel_array_s tunnel_array_t;

typedef void (*LineFlowSignal)(void *state);
typedef void (*TunnelStatusCb)(tunnel_t *);
typedef void (*TunnelChainFn)(tunnel_t *, tunnel_chain_t *info);
typedef void (*TunnelIndexFn)(tunnel_t *, tunnel_array_t *arr, uint16_t* index, uint16_t* mem_offset);
typedef void (*TunnelFlowRoutineInit)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePayload)(tunnel_t *, line_t *line, sbuf_t *payload);
typedef void (*TunnelFlowRoutineEst)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineFin)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePause)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineResume)(tunnel_t *, line_t *line);
typedef splice_retcode_t (*TunnelFlowRoutineSplice)(tunnel_t *, line_t *line, int pipe_fd, size_t len);

typedef struct pipeline_s
{
    atomic_bool closed;
    atomic_uint pipeline_refc;
    // compiler will insert padding here
    struct line_s *up;
    struct line_s *dw;
} pipe_line_t;

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
    TunnelStatusCb onPrepair;
    TunnelStatusCb onStart;

    uint16_t tstate_size;
    uint16_t lstate_size;

    uint16_t cstate_offset;
    uint16_t chain_index;

    node_t         *node;
    tunnel_chain_t *chain;


    uint8_t state[] __attribute__((aligned(sizeof(void *))));
};

tunnel_t *tunnelCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size);
void      tunnelDestroy(tunnel_t *self);

static inline void tunnelSetState(tunnel_t *self, void *state)
{
    memoryCopy(&(self->state[0]), state, self->tstate_size);
}

void tunnelBind(tunnel_t *from, tunnel_t *to);
void tunnelBindDown(tunnel_t *from, tunnel_t *to);
void tunnelBindUp(tunnel_t *from, tunnel_t *to);
void tunnelDefaultUpStreamInit(tunnel_t *self, line_t *line);
void tunnelDefaultUpStreamEst(tunnel_t *self, line_t *line);
void tunnelDefaultUpStreamFin(tunnel_t *self, line_t *line);
void tunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);
void tunnelDefaultUpStreamPause(tunnel_t *self, line_t *line);
void tunnelDefaultUpStreamResume(tunnel_t *self, line_t *line);
void tunnelDefaultdownStreamInit(tunnel_t *self, line_t *line);
void tunnelDefaultdownStreamEst(tunnel_t *self, line_t *line);
void tunnelDefaultdownStreamFin(tunnel_t *self, line_t *line);
void tunnelDefaultdownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);
void tunnelDefaultDownStreamPause(tunnel_t *self, line_t *line);
void tunnelDefaultDownStreamResume(tunnel_t *self, line_t *line);
void tunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc);
void tunnelDefaultOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void tunnelDefaultOnPrepair(tunnel_t *t);
void tunnelDefaultOnStart(tunnel_t *t);

// void pipeUpStream(context_t *c);
// void pipeDownStream(context_t *c);

static tunnel_chain_t* tunnelGetChain(tunnel_t *self)
{
    return self->chain;
}

static node_t* tunnelGetNode(tunnel_t *self)
{
    return self->node;
}

static uint16_t tunnelGetLocalStateSize(tunnel_t *self)
{
    return self->tstate_size;
}

static uint16_t tunnelGetLineStateSize(tunnel_t *self)
{
    return self->tstate_size;
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
