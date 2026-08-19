#pragma once

/*
 * Core tunnel interface, callback types, and default tunnel behavior.
 */

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
typedef void (*TunnelLifecycleCb)(tunnel_t *, const ww_lifecycle_context_t *context);
typedef void (*TunnelWorkerLifecycleCb)(tunnel_t *, wid_t wid, const ww_lifecycle_context_t *context);
typedef void (*TunnelChainFn)(tunnel_t *, tunnel_chain_t *chain);
/*
 * onIndex runs once after layer resolution and topology expansion have reached
 * a fixed point. The chain topology and its solved edge domains are final by
 * then; implementations may consume them, but must not mutate the chain.
 */
typedef void (*TunnelIndexFn)(tunnel_t *, uint16_t index, uint32_t *mem_offset);
/*
 * Runs after each successful layer solve and before indexing. The callback sees
 * the current solved topology snapshot, which is not necessarily final. It may
 * derive state from that snapshot and may materialize private topology. Return
 * true if and only if topology changed; that immediately invalidates the
 * snapshot and makes NodeManager solve again. Callbacks must tolerate repeated
 * calls. The topology is final only after every callback in a complete pass
 * reports no change.
 */
typedef bool (*TunnelSolvedTopologyFn)(tunnel_t *, tunnel_chain_t *chain);
typedef void (*TunnelFlowRoutineInit)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePayload)(tunnel_t *, line_t *line, sbuf_t *payload);
typedef void (*TunnelFlowRoutineEst)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineFin)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutinePause)(tunnel_t *, line_t *line);
typedef void (*TunnelFlowRoutineResume)(tunnel_t *, line_t *line);
typedef splice_retcode_t (*TunnelFlowRoutineSplice)(tunnel_t *, line_t *line, int pipe_fd, size_t len);

/*
    tunnel_t is part of the external-node ABI. External node libraries allocate
    tunnels through tunnelCreate(), assign these public callbacks directly, and
    access the aligned flexible state through the inline helpers below. Do not
    move historical members. A new member must occupy proven alignment padding
    or be introduced as an explicit, versioned ABI break.

    Tunnel is just a doubly linked list, it has its own state, per connection state is stored in line structure
    which later gets accessed by the chain_index which is fixed.

    node(Create) -> onChain -> [solve -> onSolvedTopology]* -> onIndex -> onPrepare -> onStart -> node(Destroy)
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

    TunnelChainFn           onChain;
    TunnelIndexFn           onIndex;
    TunnelStatusCb          onPrepare;
    TunnelStatusCb          onStart;
    TunnelLifecycleCb       onQuiesceRequest;
    TunnelWorkerLifecycleCb onWorkerQuiesce;
    TunnelLifecycleCb       onQuiesceWait;
    TunnelWorkerLifecycleCb onWorkerStop;
    TunnelLifecycleCb       onStop;
    TunnelLifecycleCb       onDestroy;

    uint32_t tstate_size;
    uint32_t lstate_size;

    uint32_t lstate_offset;
    uint16_t chain_index;

    node_t         *node;
    tunnel_chain_t *chain;

    /*
     * Optional pre-indexing hook for a tunnel whose runtime orientation or
     * private topology depends on solved adjacent layer domains. See the
     * TunnelSolvedTopologyFn contract above. Tunnels that only need to consume
     * the final solution may do so in onIndex instead. (as of writing this only WireGuardDevice used this)
     *
     * This pointer occupies historical alignment padding: state[] remains at
     * the same cache-line-aligned offset, preserving the external tunnel ABI.
     * Old external nodes leave it NULL, which is the default no-op behavior.
     */
    TunnelSolvedTopologyFn onSolvedTopology;

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
tunnel_t *tunnelCreate(node_t *node, size_t tstate_size, size_t lstate_size);

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
 * @brief Resolves the callable upstream entry of a branch bound below @p owner.
 *
 * When a tunnel binds another node below itself (a fallback, route target,
 * destination, or helper branch) and later drives it directly through
 * tunnelUpStream*() / tunnelDownStream*(), it must call the branch *entry*, not
 * the raw node instance it was given. A target may insert internal tunnels in
 * front of itself while chaining (for example a connector's domain-setup +
 * DomainResolver pair), in which case the real entry is the head that ends up
 * bound directly below @p owner.
 *
 * This walks @p target's prev-links until it reaches the tunnel whose prev is
 * @p owner. For a target that inserts nothing, @p target itself is returned.
 *
 * Must be called only after @p target has been chained (so any internal tunnels
 * are already inserted and prev-linked back toward @p owner).
 *
 * @param owner  The tunnel that bound @p target below itself.
 * @param target The raw bound node instance.
 * @return The branch entry tunnel, or NULL if @p target is not reachable from
 *         @p owner.
 */
tunnel_t *tunnelGetBranchEntry(tunnel_t *owner, tunnel_t *target);

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
 * This call, and any nested onChain callback, may merge @p tc into an already-built
 * downstream chain and destroy @p tc. A custom onChain implementation that continues
 * afterward must reacquire the active chain with tunnelGetChain(t) before reusing it.
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
void tunnelDefaultOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);

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
 * @brief Default function to stop the tunnel.
 *
 * @param t Pointer to the tunnel.
 */
void tunnelDefaultOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void tunnelDefaultOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void tunnelDefaultOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context);
void tunnelDefaultOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);

/**
 * @brief Default function to stop worker-local tunnel resources.
 *
 * @param t Tunnel instance.
 * @param wid Worker whose local resources are being stopped.
 */
void tunnelDefaultOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void tunnelDefaultOnDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);

void tunnelOwnedChildQuiesceRequest(tunnel_t *child);
void tunnelOwnedChildWorkerQuiesce(tunnel_t *child, wid_t wid);
void tunnelOwnedChildQuiesceWait(tunnel_t *child);
void tunnelOwnedChildWorkerStop(tunnel_t *child, wid_t wid);
void tunnelOwnedChildStop(tunnel_t *child);
void tunnelOwnedChildDestroy(tunnel_t *child);

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
    return self->lstate_size;
}

/**
 * @brief True when rounding @p size up to a cache line would wrap.
 *
 * The rounding below is 32-bit arithmetic, so UINT32_MAX became zero and
 * tunnelCreate() returned a tunnel whose state sizes were both zero instead of
 * reporting the overflow its contract promises. Callers must reject first.
 */
static inline bool tunnelTryAlignStateSize(size_t size, uint32_t *aligned_size)
{
    const size_t maximum = (size_t) UINT32_MAX - ((size_t) kCpuLineCacheSize - 1U);
    if (size > maximum || aligned_size == NULL)
    {
        return false;
    }

    *aligned_size = (uint32_t) ((size + (size_t) kCpuLineCacheSize - 1U) & ~((size_t) kCpuLineCacheSize - 1U));
    return true;
}

static bool tunnelStateSizeOverflows(uint32_t size)
{
    uint32_t aligned_size;
    return ! tunnelTryAlignStateSize((size_t) size, &aligned_size);
}

/**
 * @brief Retrieves the correctly aligned state size.
 *
 * Only valid for a size that tunnelStateSizeOverflows() does not reject; the caller is
 * responsible for that check because this cannot report a failure.
 *
 * @param size Size to be aligned.
 * @return uint32_t Correctly aligned state size.
 */
static uint32_t tunnelGetCorrectAlignedStateSize(uint32_t size)
{
    uint32_t   aligned_size = 0;
    const bool valid        = tunnelTryAlignStateSize((size_t) size, &aligned_size);
    assert(valid);
    discard valid;
    return aligned_size;
}

/**
 * @brief Retrieves the correctly aligned line state size.
 *
 * @param size Size to be aligned.
 * @return uint32_t Correctly aligned line state size.
 */
static uint32_t tunnelGetCorrectAlignedLineStateSize(uint32_t size)
{
    uint32_t   aligned_size = 0;
    const bool valid        = tunnelTryAlignStateSize((size_t) size, &aligned_size);
    assert(valid);
    discard valid;
    return aligned_size;
}

/**
 * @brief Initializes the upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamInit(tunnel_t *self, line_t *line)
{
    self->fnInitU(self, line);
}

/**
 * @brief Establishes the upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamEst(tunnel_t *self, line_t *line)
{
    self->fnEstU(self, line);
}

/**
 * @brief Finalizes the upstream line.
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
 * @brief Pauses the upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamPause(tunnel_t *self, line_t *line)
{
    self->fnPauseU(self, line);
}

/**
 * @brief Resumes the upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelUpStreamResume(tunnel_t *self, line_t *line)
{
    self->fnResumeU(self, line);
}

/**
 * @brief Initializes the downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamInit(tunnel_t *self, line_t *line)
{
    self->fnInitD(self, line);
}

/**
 * @brief Establishes the downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamEst(tunnel_t *self, line_t *line)
{
    self->fnEstD(self, line);
}

/**
 * @brief Finalizes the downstream line.
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
 * @brief Pauses the downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamPause(tunnel_t *self, line_t *line)
{
    self->fnPauseD(self, line);
}

/**
 * @brief Resumes the downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelDownStreamResume(tunnel_t *self, line_t *line)
{
    self->fnResumeD(self, line);
}

/**
 * @brief Initializes the next upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamInit(tunnel_t *self, line_t *line)
{
    self->next->fnInitU(self->next, line);
}

/**
 * @brief Establishes the next upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamEst(tunnel_t *self, line_t *line)
{
    self->next->fnEstU(self->next, line);
}

/**
 * @brief Finalizes the next upstream line.
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
 * @brief Pauses the next upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamPause(tunnel_t *self, line_t *line)
{
    self->next->fnPauseU(self->next, line);
}

/**
 * @brief Resumes the next upstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelNextUpStreamResume(tunnel_t *self, line_t *line)
{
    self->next->fnResumeU(self->next, line);
}

/**
 * @brief Initializes the prev downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamInit(tunnel_t *self, line_t *line)
{
    self->prev->fnInitD(self->prev, line);
}

/**
 * @brief Establishes the prev downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamEst(tunnel_t *self, line_t *line)
{
    self->prev->fnEstD(self->prev, line);
}

/**
 * @brief Finalizes the prev downstream line.
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
 * @brief Pauses the prev downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamPause(tunnel_t *self, line_t *line)
{
    self->prev->fnPauseD(self->prev, line);
}

/**
 * @brief Resumes the prev downstream line.
 *
 * @param self Pointer to the tunnel.
 * @param line Pointer to the line.
 */
static inline void tunnelPrevDownStreamResume(tunnel_t *self, line_t *line)
{
    self->prev->fnResumeD(self->prev, line);
}
