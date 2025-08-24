#pragma once
#include "address_context.h"
#include "buffer_pool.h"
#include "chain.h"
#include "generic_pool.h"
#include "shiftbuffer.h"
#include "wlibc.h"
#include "wloop.h"
#include "worker.h"

/*
    Tunnels basically encapsulate/decapsulate the packets and pass them to the next tunnel.
    Something like this:

    ------------------------------ chain ---------------------------------

      --------------            --------------            --------------
      |            | ---------> |            | ---------> |            |
      |  Tunnel 1  |            |  Tunnel 2  |            |  Tunnel 3  |
      |            | <--------- |            | <--------- |            |
      --------------            --------------            --------------

    ----------------------------------------------------------------------

    Tunnel 1 and 3 are also called adapters since they have an OS socket to read and write to.

    Nodes are mostly pairs, meaning that one pair is the client (imagine a node that encrypts data)
    and the other node is the server (imagine a node that decrypts data).

    We don't care what a node is doing with packets
    as long as it provides an upstream and downstream function, it's a node that can join the chain.

    And each tunnel knows that every connection can belong to any thread,
    so we created everything thread-local, such as buffer pools, event loops, etc...
*/

typedef struct node_s         node_t;
typedef struct tunnel_s       tunnel_t;
typedef struct line_s         line_t;
typedef struct tunnel_chain_s tunnel_chain_t;
typedef struct tunnel_array_s tunnel_array_t;

typedef void (*TunnelStatusCb)(tunnel_t *);
typedef void (*TunnelChainFn)(tunnel_t *, tunnel_chain_t *chain);
typedef void (*TunnelIndexFn)(tunnel_t *, uint16_t index, uint16_t *mem_offset);
typedef void (*TunnelFlowRoutineInit)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePayload)(tunnel_t *, line_t *line, sbuf_t *payload);
typedef void (*TunnelFlowRoutineEst)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineFin)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePause)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineResume)(tunnel_t *, line_t *line);
typedef splice_retcode_t (*TunnelFlowRoutineSplice)(tunnel_t *, line_t *line, int pipe_fd, size_t len);

/*
    Tunnel is just a doubly linked list, it has its own state, per connection state is stored in line structure
    which later gets accessed by the chain_index which is fixed.

    node(Create) -> onChain -> onChainingComplete -> onIndex -> onChainStart -> node(Destroy)
*/
struct tunnel_s
{
    tunnel_t *next, *prev;

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
    TunnelStatusCb onPrepare;
    TunnelStatusCb onStart;
    TunnelStatusCb onDestroy;

    uint32_t tstate_size;
    uint32_t lstate_size;

    uint16_t lstate_offset;
    uint16_t chain_index;

    node_t         *node;
    tunnel_chain_t *chain;
    uintptr_t       memptr;

    // tunnel itself will be aligned to cache line when allocating memory
    MSVC_ATTR_ALIGNED_LINE_CACHE uint8_t state[] GNU_ATTR_ALIGNED_LINE_CACHE;
};

/**
 * @brief Creates a new tunnel instance.
 *
 * @param node Pointer to the node.
 * @param tstate_size Size of the tunnel state.
 * @param lstate_size Size of the line state.
 * @return tunnel_t* Pointer to the created tunnel.
 */
tunnel_t *tunnelCreate(node_t *node, uint32_t tstate_size, uint32_t lstate_size);

/**
 * @brief Destroys a tunnel instance.
 *
 * @param self Pointer to the tunnel.
 */
void tunnelDestroy(tunnel_t *self);

/**
 * @brief Sets the state of the tunnel.
 *
 * @param self Pointer to the tunnel.
 * @param state Pointer to the state.
 */
static inline void tunnelSetState(tunnel_t *self, void *state)
{
    memoryCopy(&(self->state[0]), state, self->tstate_size);
}

/**
 * @brief Binds two tunnels together (from <-> to).
 *
 * @param from Pointer to the source tunnel.
 * @param to Pointer to the destination tunnel.
 */
void tunnelBind(tunnel_t *from, tunnel_t *to);

/**
 * @brief Binds a tunnel as the downstream of another tunnel.
 *
 * @param from Pointer to the source tunnel.
 * @param to Pointer to the destination tunnel.
 */
void tunnelBindDown(tunnel_t *from, tunnel_t *to);

/**
 * @brief Binds a tunnel as the upstream of another tunnel.
 *
 * @param from Pointer to the source tunnel.
 * @param to Pointer to the destination tunnel.
 */
void tunnelBindUp(tunnel_t *from, tunnel_t *to);

/**
 * @brief Default upstream initialization function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultUpStreamInit(tunnel_t *self, line_t *line);

/**
 * @brief Default upstream establishment function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultUpStreamEst(tunnel_t *self, line_t *line);

/**
 * @brief Default upstream finish function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultUpStreamFin(tunnel_t *self, line_t *line);

/**
 * @brief Default upstream payload function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
void tunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);

/**
 * @brief Default upstream pause function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultUpStreamPause(tunnel_t *self, line_t *line);

/**
 * @brief Default upstream resume function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultUpStreamResume(tunnel_t *self, line_t *line);

/**
 * @brief Default downstream initialization function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultDownStreamInit(tunnel_t *self, line_t *line);

/**
 * @brief Default downstream establishment function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultDownStreamEst(tunnel_t *self, line_t *line);

/**
 * @brief Default downstream finish function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultDownStreamFinish(tunnel_t *self, line_t *line);

/**
 * @brief Default downstream payload function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
void tunnelDefaultDownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);

/**
 * @brief Default downstream pause function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultDownStreamPause(tunnel_t *self, line_t *line);

/**
 * @brief Default downstream resume function.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void tunnelDefaultDownStreamResume(tunnel_t *self, line_t *line);

/**
 * @brief Default function to handle tunnel chaining.
 *
 * @param t Pointer to the tunnel.
 * @param tc Pointer to the tunnel chain.
 */
void tunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc);

/**
 * @brief Default function to handle tunnel indexing.
 *
 * @param arr Pointer to the tunnel array.
 * @param index index.
 * @param mem_offset Pointer to the memory offset.
 */
void tunnelDefaultOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);

/**
 * @brief Default function to prepare the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
void tunnelDefaultOnPrepare(tunnel_t *t);

/**
 * @brief Default function to start the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
void tunnelDefaultOnStart(tunnel_t *t);

/**
 * @brief Retrieves the state of the tunnel.
 *
 * @param self Pointer to the tunnel.
 * @return void* Pointer to the state of the tunnel.
 */
static void *tunnelGetState(tunnel_t *self)
{
    return &(self->state[0]);
}

/**
 * @brief Retrieves the chain of the tunnel.
 *
 * @param self Pointer to the tunnel.
 * @return tunnel_chain_t* Pointer to the chain of the tunnel.
 */
static tunnel_chain_t *tunnelGetChain(tunnel_t *self)
{
    return self->chain;
}

/**
 * @brief Retrieves the node of the tunnel.
 *
 * @param self Pointer to the tunnel.
 * @return node_t* Pointer to the node of the tunnel.
 */
static node_t *tunnelGetNode(tunnel_t *self)
{
    return self->node;
}

/**
 * @brief Retrieves the state size of the tunnel.
 *
 * @param self Pointer to the tunnel.
 * @return uint32_t State size of the tunnel.
 */
static uint32_t tunnelGetStateSize(tunnel_t *self)
{
    return self->tstate_size;
}

/**
 * @brief Retrieves the line state size of the tunnel.
 *
 * @param self Pointer to the tunnel.
 * @return uint32_t Line state size of the tunnel.
 */
static uint32_t tunnelGetLineStateSize(tunnel_t *self)
{
    return self->tstate_size;
}

/**
 * @brief Retrieves the correctly aligned state size.
 *
 * @param size Size to be aligned.
 * @return uint16_t Correctly aligned state size.
 */
static uint16_t tunnelGetCorrectAlignedStateSize(uint32_t size)
{
    return (size + kCpuLineCacheSize - 1) & ~(kCpuLineCacheSize - 1);
}

/**
 * @brief Retrieves the correctly aligned line state size.
 *
 * @param size Size to be aligned.
 * @return uint16_t Correctly aligned line state size.
 */
static uint16_t tunnelGetCorrectAlignedLineStateSize(uint16_t size)
{
    return (size + kCpuLineCacheSize - 1) & ~(kCpuLineCacheSize - 1);
}

/**
 * @brief Initializes the upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamInit(tunnel_t *self, line_t *line)
{
    self->fnInitU(self, line);
}

/**
 * @brief Establishes the upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamEst(tunnel_t *self, line_t *line)
{
    self->fnEstU(self, line);
}

/**
 * @brief Finalizes the upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamFin(tunnel_t *self, line_t *line)
{
    self->fnFinU(self, line);
}

/**
 * @brief Handles upstream payload.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
static inline void tunnelUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    self->fnPayloadU(self, line, payload);
}

/**
 * @brief Pauses the upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamPause(tunnel_t *self, line_t *line)
{
    self->fnPauseU(self, line);
}

/**
 * @brief Resumes the upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamResume(tunnel_t *self, line_t *line)
{
    self->fnResumeU(self, line);
}

/**
 * @brief Initializes the downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamInit(tunnel_t *self, line_t *line)
{
    self->fnInitD(self, line);
}

/**
 * @brief Establishes the downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamEst(tunnel_t *self, line_t *line)
{
    self->fnEstD(self, line);
}

/**
 * @brief Finalizes the downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamFin(tunnel_t *self, line_t *line)
{
    self->fnFinD(self, line);
}

/**
 * @brief Handles downstream payload.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
static inline void tunnelDownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    self->fnPayloadD(self, line, payload);
}

/**
 * @brief Pauses the downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamPause(tunnel_t *self, line_t *line)
{
    self->fnPauseD(self, line);
}

/**
 * @brief Resumes the downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamResume(tunnel_t *self, line_t *line)
{
    self->fnResumeD(self, line);
}

/**
 * @brief Initializes the next upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamInit(tunnel_t *self, line_t *line)
{
    self->next->fnInitU(self->next, line);
}

/**
 * @brief Establishes the next upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamEst(tunnel_t *self, line_t *line)
{
    self->next->fnEstU(self->next, line);
}

/**
 * @brief Finalizes the next upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamFinish(tunnel_t *self, line_t *line)
{
    self->next->fnFinU(self->next, line);
}

/**
 * @brief Handles the next upstream payload.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
static inline void tunnelNextUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    self->next->fnPayloadU(self->next, line, payload);
}

/**
 * @brief Pauses the next upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamPause(tunnel_t *self, line_t *line)
{
    self->next->fnPauseU(self->next, line);
}

/**
 * @brief Resumes the next upstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamResume(tunnel_t *self, line_t *line)
{
    self->next->fnResumeU(self->next, line);
}

/**
 * @brief Initializes the prev downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamInit(tunnel_t *self, line_t *line)
{
    self->prev->fnInitD(self->prev, line);
}

/**
 * @brief Establishes the prev downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamEst(tunnel_t *self, line_t *line)
{
    self->prev->fnEstD(self->prev, line);
}

/**
 * @brief Finalizes the prev downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamFinish(tunnel_t *self, line_t *line)
{
    self->prev->fnFinD(self->prev, line);
}

/**
 * @brief Handles the prev downstream payload.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
static inline void tunnelPrevDownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    self->prev->fnPayloadD(self->prev, line, payload);
}

/**
 * @brief Pauses the prev downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamPause(tunnel_t *self, line_t *line)
{
    self->prev->fnPauseD(self->prev, line);
}

/**
 * @brief Resumes the prev downstream pipeline.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamResume(tunnel_t *self, line_t *line)
{
    self->prev->fnResumeD(self->prev, line);
}
