#include "DomainResolver/structure.h"

static bool user_destroyed;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void destroyUserState(tunnel_t *resolver, tunnel_t *owner, line_t *line, void *state)
{
    discard resolver;
    discard owner;
    discard line;
    require(*(uint8_t *) state == 0x5A, "user destroy hook received the wrong embedded state");
    user_destroyed = true;
}

int main(void)
{
    node_t    node     = {.type = (char *) "DomainResolver"};
    tunnel_t *resolver = tunnelCreate(&node, sizeof(domainresolver_tstate_t), sizeof(domainresolver_lstate_t));
    require(resolver != NULL, "failed to create resolver layout fixture");
    domainresolverTunnelSetPrepareHook(resolver, NULL, 1, NULL, destroyUserState);
    domainresolver_tstate_t *ts = tunnelGetState(resolver);
    require(ts->user_lstate_size == 32, "embedded user state was not rounded to 32 bytes");
    require(ts->user_lstate_offset == tunnelGetCorrectAlignedLineStateSize(sizeof(domainresolver_lstate_t)),
            "embedded user state has the wrong offset");
    require(resolver->lstate_size == ts->user_lstate_offset + 32, "resolver reservation differs from embedded layout");

    // Place the resolver between two ordinary slots, starting inside a cache line.
    resolver->lstate_offset  = 32;
    const uint32_t following = resolver->lstate_offset + resolver->lstate_size;
    uint32_t       item_size;
    require(tunnelchainTryComputeLineItemSize(following + 32, &item_size), "resolver line item overflowed");
    master_pool_t *master = masterpoolCreateWithCapacity(4);
    require(master != NULL, "failed to create resolver master pool");
    generic_pool_t *pools[] = {genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(master, item_size, 2)};
    require(pools[0] != NULL, "failed to create resolver line pool");
    line_t  *line   = lineCreateForWorker(0, pools, 0); // Fixture-owned normal line.
    uint8_t *states = (uint8_t *) line->tunnels_line_state;
    memorySet(states, 0xA5, 32);
    memorySet(states + following, 0xA5, 32);

    domainresolver_lstate_t *ls = lineGetState(line, resolver);
    require((uintptr_t) ls % kCpuLineCacheSize == 32, "resolver fixture starts on a cache boundary");
    void *user = domainresolverTunnelGetUserLineState(resolver, line);
    memorySet(user, 0x5A, ts->user_lstate_size);
    domainresolverLinestateInitialize(resolver, ls);
    for (size_t i = 0; i < ts->user_lstate_size; ++i)
    {
        require(((uint8_t *) user)[i] == 0, "resolver initialization did not clear embedded user state");
    }
    *(uint8_t *) user = 0x5A;
    domainresolverLinestateDestroy(resolver, line, ls);
    require(user_destroyed, "resolver did not invoke embedded-state destruction");
    for (size_t i = 0; i < following + 32; ++i)
    {
        const uint8_t expected = i < 32 || i >= following ? 0xA5 : 0;
        require(states[i] == expected, "resolver initialization or destruction overwrote a neighboring slot");
    }
    memoryZeroAligned32(states, 32);
    memoryZeroAligned32(states + following, 32);
    lineDestroy(line);
    require(masterpoolGetCheckedOut(master) == 0, "resolver line was not reclaimed");
    genericpoolDestroy(pools[0]);
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
    tunnelDestroy(resolver);
    return 0;
}
