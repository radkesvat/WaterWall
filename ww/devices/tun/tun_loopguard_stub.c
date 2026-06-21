#include "tun_loopguard.h"

// Platforms without a TUN loop-guard implementation (everything except WinDivert
// enabled Windows builds). The guard is a no-op: callers stay #ifdef-free.

tun_loopguard_t *tunLoopGuardStart(uint64_t tun_luid_value)
{
    discard tun_luid_value;
    return NULL;
}

void tunLoopGuardStop(tun_loopguard_t *guard)
{
    discard guard;
}
