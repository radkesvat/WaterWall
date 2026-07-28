/*
 * ReverseClient line-state invariant fixture.
 *
 * This translation unit sees only ReverseClient's production structure.h, so
 * the fixture uses the real reverseclient_lstate_t layout instead of a mirrored
 * prefix, and the tunnel/line arguments of a full ReverseClient chain are never
 * faked.
 */
#include "ReverseClient/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortReverseClientLinestateCase(void)
{
    // Allocated at the production line-state size and alignment so that a
    // regression which dropped the invariant would fall through into
    // memoryZeroAligned32() on valid memory and exit 0 instead of corrupting
    // the caller.
    const uint32_t lstate_size = tunnelGetCorrectAlignedLineStateSize(sizeof(reverseclient_lstate_t));

    reverseclient_lstate_t *lstate = memoryAllocateCacheAlignedZero(lstate_size);
    if (lstate == NULL)
    {
        return kAbortCaseAllocationFailed;
    }

    // A live idle handle at destroy time is the invariant under test. The
    // production path must log and abort before anything dereferences it.
    static uint64_t idle_handle_sentinel = 0;

    lstate->idle_handle = (idle_item_t *) &idle_handle_sentinel;

    reverseclientLinestateDestroy(lstate);

    memoryFreeAligned(lstate);
    return 0;
}
