#include "tunnel.h"

/*
 * Implements tunnel binding, default flow forwarding, and tunnel lifecycle.
 */

#include "loggers/internal_logger.h"
#include "managers/node_manager.h"

// Binds a tunnel as the upstream of another tunnel
void tunnelBindUp(tunnel_t *from, tunnel_t *to)
{
    from->next = to;
}

// Binds a tunnel as the downstream of another tunnel
void tunnelBindDown(tunnel_t *from, tunnel_t *to)
{
    // assert(to->dw == NULL); // 2 nodes cannot chain to 1 exact node
    // such chains are possible by a generic listener adapter
    // but the cyclic reference detection is already done in node map
    to->prev = from;
}

// Binds two tunnels together (from <-> to)
void tunnelBind(tunnel_t *from, tunnel_t *to)
{
    tunnelBindUp(from, to);
    tunnelBindDown(from, to);
}

// Resolves the callable upstream entry of a branch bound below `owner`.
// A target may insert internal tunnels in front of itself while chaining, so the
// real entry is the head bound directly below `owner`. Walk target's prev-links
// until the tunnel whose prev is `owner` is found; a target that inserts nothing
// returns itself. Returns NULL if target is not reachable from owner.
tunnel_t *tunnelGetBranchEntry(tunnel_t *owner, tunnel_t *target)
{
    tunnel_t *entry = target;
    for (uint16_t i = 0; i < kMaxChainLen && entry != NULL; ++i)
    {
        if (entry->prev == owner)
        {
            return entry;
        }

        entry = entry->prev;
    }

    return NULL;
}

// Default upstream initialization function
void tunnelDefaultUpStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnInitU(self->next, line);
}

// Default upstream establishment function
void tunnelDefaultUpStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnEstU(self->next, line);
}

// Default upstream finalization function
void tunnelDefaultUpStreamFin(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnFinU(self->next, line);
}

// Default upstream payload function
void tunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    assert(self->next != NULL);
    self->next->fnPayloadU(self->next, line, payload);
}

// Default upstream pause function
void tunnelDefaultUpStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnPauseU(self->next, line);
}

// Default upstream resume function
void tunnelDefaultUpStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    self->next->fnResumeU(self->next, line);
}

// Default downstream initialization function
void tunnelDefaultDownStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->prev != NULL);
    self->prev->fnInitD(self->prev, line);
}

// Default downstream establishment function
void tunnelDefaultDownStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->prev != NULL);
    self->prev->fnEstD(self->prev, line);
}

// Default downstream finalization function
void tunnelDefaultDownStreamFinish(tunnel_t *self, line_t *line)
{
    assert(self->prev != NULL);
    self->prev->fnFinD(self->prev, line);
}

// Default downstream payload function
void tunnelDefaultDownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    assert(self->prev != NULL);
    self->prev->fnPayloadD(self->prev, line, payload);
}

// Default downstream pause function
void tunnelDefaultDownStreamPause(tunnel_t *self, line_t *line)
{
    assert(self->prev != NULL);
    self->prev->fnPauseD(self->prev, line);
}

// Default downstream resume function
void tunnelDefaultDownStreamResume(tunnel_t *self, line_t *line)
{
    assert(self->prev != NULL);
    self->prev->fnResumeD(self->prev, line);
}

// Default function to handle tunnel chaining
void tunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc)
{
    node_t *node = tunnelGetNode(t);

    if (node->hash_next == 0x0)
    {
        tunnelchainInsert(tc, t);
        return;
    }

    node_t *next = nodemanagerGetConfigNodeByHash(node->node_manager_config, node->hash_next);

    if (next == NULL)
    {
        LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", node->name, node->next);
        terminateProgram(1);
    }

    assert(next->instance); // every node in node map is created before chaining

    tunnel_t *tnext = next->instance;
    if (tnext->prev != NULL)
    {
        LOGF("Node Map Failure: Node (%s) wanted to bind to (%s) which is already bounded by %s",
             t->node->name,
             tnext->node->name,
             tnext->prev->node->name);
        terminateProgram(1);
    }

    tunnelBind(t, tnext);

    tunnelchainInsert(tc, t);

    if (tnext->chain != NULL)
    {
        // this can happen when something like bridge node is present in the chain
        tunnelchainCombine(tnext->chain, tc);
    }
    else
    {
        tnext->onChain(tnext, tc);
    }
}

// Default function to handle tunnel indexing
void tunnelDefaultOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset)
{
    t->chain_index   = index;
    t->lstate_offset = *mem_offset;

    *mem_offset += t->lstate_size;
}

// Default function to prepare the tunnel
void tunnelDefaultOnPrepare(tunnel_t *t)
{
    discard t;
}

// Default function to start the tunnel
void tunnelDefaultOnStart(tunnel_t *t)
{
    discard t;
}

void tunnelDefaultOnStop(tunnel_t *t)
{
    discard t;
}

void tunnelDefaultOnWorkerStop(tunnel_t *t, wid_t wid)
{
    discard t;
    discard wid;
}

// Creates a new tunnel instance
tunnel_t *tunnelCreate(node_t *node, uint32_t tstate_size, uint32_t lstate_size)
{
    tstate_size = tunnelGetCorrectAlignedStateSize(tstate_size);
    lstate_size = tunnelGetCorrectAlignedLineStateSize(lstate_size);

    const size_t required_size = sizeof(tunnel_t) + (size_t) tstate_size;
    if (required_size < sizeof(tunnel_t))
    {
        return NULL;
    }

    // allocate memory, placing tunnel_t at a line cache address boundary
    tunnel_t *tunnel_ptr = memoryAllocateCacheAligned(required_size);
    if (tunnel_ptr == NULL)
    {
        // Handle memory allocation failure
        return NULL;
    }

    memorySet(tunnel_ptr, 0, sizeof(tunnel_t) + tstate_size);

    *tunnel_ptr = (tunnel_t) {.fnInitU     = &tunnelDefaultUpStreamInit,
                              .fnInitD     = &tunnelDefaultDownStreamInit,
                              .fnPayloadU  = &tunnelDefaultUpStreamPayload,
                              .fnPayloadD  = &tunnelDefaultDownStreamPayload,
                              .fnEstU      = &tunnelDefaultUpStreamEst,
                              .fnEstD      = &tunnelDefaultDownStreamEst,
                              .fnFinU      = &tunnelDefaultUpStreamFin,
                              .fnFinD      = &tunnelDefaultDownStreamFinish,
                              .fnPauseU    = &tunnelDefaultUpStreamPause,
                              .fnPauseD    = &tunnelDefaultDownStreamPause,
                              .fnResumeU   = &tunnelDefaultUpStreamResume,
                              .fnResumeD   = &tunnelDefaultDownStreamResume,
                              .onChain     = &tunnelDefaultOnChain,
                              .onIndex     = &tunnelDefaultOnIndex,
                              .onPrepare   = &tunnelDefaultOnPrepare,
                              .onStart     = &tunnelDefaultOnStart,
                              .onStop      = &tunnelDefaultOnStop,
                              .onWorkerStop = &tunnelDefaultOnWorkerStop,
                              .onDestroy   = &tunnelDestroy,
                              .tstate_size = tstate_size,
                              .lstate_size = lstate_size,
                              .node        = node};

    return tunnel_ptr;
}

// Destroys a tunnel instance
void tunnelDestroy(tunnel_t *self)
{
    memoryFreeAligned(self);
}
