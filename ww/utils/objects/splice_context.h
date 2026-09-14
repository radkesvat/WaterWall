#pragma once

#include "wlibc.h"

enum
{
    kSpliceContextMaxTunnels = 64
};

typedef struct splice_context_s
{
    const uint16_t tunnel_count;
    uint64_t       splice_blockers;
} splice_context_t;

/** Allocate a context and initially block every tunnel; abort on allocation failure. */
splice_context_t *splicecontextCreate(uint16_t tunnel_count);

/** Free the context. NULL is allowed. */
void splicecontextDestroy(splice_context_t *context);

/** Return the tunnel count fixed at context creation. */
static inline uint16_t splicecontextGetTunnelCount(const splice_context_t *context)
{
    return context->tunnel_count;
}

/** Return whether at least one tunnel still blocks splicing. */
static inline bool splicecontextIsBlocked(const splice_context_t *context)
{
    return context->splice_blockers != 0;
}

/** Set a tunnel's blocker; a fully unblocked context cannot be blocked again. */
static inline void splicecontextBlock(splice_context_t *context, uint16_t tunnel_index)
{
    assert(tunnel_index < context->tunnel_count);
    if (UNLIKELY(! splicecontextIsBlocked(context)))
    {
        printError("splicecontextBlock: tunnel %u cannot block splicing after all tunnels have unblocked it\n",
                   (unsigned int) tunnel_index);
        abortProgramNow(1);
    }
    context->splice_blockers |= UINT64_C(1) << tunnel_index;
}

/** Clear one tunnel's blocker; a zero mask means every tunnel has unblocked splicing. */
static inline void splicecontextUnblock(splice_context_t *context, uint16_t tunnel_index)
{
    assert(tunnel_index < context->tunnel_count);
    context->splice_blockers &= ~(UINT64_C(1) << tunnel_index);
}
