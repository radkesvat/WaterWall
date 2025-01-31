#pragma once
#include "buffer_pool.h"
#include "generic_pool.h"
#include "connection_context.h"
#include "wlibc.h"
#include "wloop.h"
#include "chain.h"
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


typedef struct node_s         node_t;
typedef struct tunnel_s       tunnel_t;
typedef struct line_s         line_t;
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

// typedef struct pipeline_s
// {
//     atomic_bool closed;
//     atomic_uint pipeline_refc;
//     // compiler will insert padding here
//     struct line_s *up;
//     struct line_s *dw;
// } pipe_line_t;

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

    uint16_t lstate_offset;
    uint16_t chain_index;

    node_t         *node;
    tunnel_chain_t *chain;


    uint8_t state[] __attribute__((aligned(kCpuLineCacheSize)));
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

static void* tunnelGetState(tunnel_t *self)
{
    return &(self->state[0]);
}

static tunnel_chain_t* tunnelGetChain(tunnel_t *self)
{
    return self->chain;
}

static node_t* tunnelGetNode(tunnel_t *self)
{
    return self->node;
}

static uint16_t tunnelGetStateSize(tunnel_t *self)
{
    return self->tstate_size;
}

static uint16_t tunnelGetLineStateSize(tunnel_t *self)
{
    return self->tstate_size;
}

static uint16_t tunnelGetCorrectAllignedStateSize(uint16_t size)
{
    return (size + kCpuLineCacheSize - 1) & ~(kCpuLineCacheSize - 1);
}

static uint16_t tunnelGetCorrectAllignedLineStateSize(uint16_t size)
{
    return (size + kCpuLineCacheSize - 1) & ~(kCpuLineCacheSize - 1);
}




