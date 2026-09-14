#include "splice_context.h"

splice_context_t *splicecontextCreate(uint16_t tunnel_count)
{
    assert(tunnel_count <= kSpliceContextMaxTunnels);
    splice_context_t *context = memoryAllocateZero(sizeof(*context));
    if (UNLIKELY(context == NULL))
    {
        printError("splicecontextCreate: failed to allocate splice context for %u tunnels\n",
                   (unsigned int) tunnel_count);
        abortProgramNow(1);
    }
    const splice_context_t initial = {
        .tunnel_count    = tunnel_count,
        .splice_blockers = tunnel_count == 64 ? UINT64_MAX : (UINT64_C(1) << tunnel_count) - 1U,
    };
    memoryCopy(context, &initial, sizeof(initial));
    return context;
}

void splicecontextDestroy(splice_context_t *context)
{
    memoryFree(context);
}
