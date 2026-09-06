#include "wwapi.h"

enum
{
    kTunnelCount   = 19,
    kLineStateSize = 3712
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void testLargeOffsets(void)
{
    node_t node = {
        .name        = (char *) "line-state-index-test",
        .type        = (char *) "TestTunnel",
        .layer_group = kNodeLayer4,
    };
    tunnel_chain_t *chain = tunnelchainCreate(0);
    tunnel_t       *tunnels[kTunnelCount];

    require(chain != NULL, "failed to create test chain");

    for (uint16_t i = 0; i < kTunnelCount; ++i)
    {
        tunnels[i] = tunnelCreate(&node, 0, kLineStateSize);
        require(tunnels[i] != NULL, "failed to create test tunnel");
        require(tunnels[i]->lstate_size == kLineStateSize, "unexpected aligned line-state size");
        tunnelchainInsert(chain, tunnels[i]);
    }

    uint32_t mem_offset = 0;
    for (uint16_t i = 0; i < kTunnelCount; ++i)
    {
        tunnels[i]->onIndex(tunnels[i], i, &mem_offset);
    }

    require(tunnels[18]->lstate_offset == 66816U, "19th line-state offset wrapped below 64 KiB");
    require(mem_offset == 70528U, "indexed line-state total is incorrect");
    require(mem_offset == chain->sum_line_state_size, "indexed and accumulated line-state totals differ");

    tunnelchainDestroy(chain);
    for (uint16_t i = 0; i < kTunnelCount; ++i)
    {
        tunnelDestroy(tunnels[i]);
    }
}

static void testDenseSlots(void)
{
    static const uint32_t sizes[]    = {0, 1, 31, 32, 33, 63, 64, 65, 96, 97};
    static const uint32_t reserved[] = {0, 32, 32, 32, 64, 64, 64, 96, 96, 128};
    tunnel_t             *tunnels[sizeof(sizes) / sizeof(sizes[0])];
    node_t                node  = {.type = (char *) "TestTunnel"};
    tunnel_chain_t       *chain = tunnelchainCreate(1);
    require(chain != NULL, "failed to create dense chain");

    uint32_t offset = 0;
    for (uint16_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
    {
        tunnels[i] = tunnelCreate(&node, 1, sizes[i]);
        require(tunnels[i] != NULL, "failed to create dense tunnel");
        require(tunnels[i]->tstate_size == kCpuLineCacheSize, "tunnel-wide alignment changed");
        require(tunnels[i]->lstate_size == reserved[i], "line-state reservation is not dense");
        tunnelchainInsert(chain, tunnels[i]);
        tunnels[i]->onIndex(tunnels[i], i, &offset);
    }
    require(offset == chain->sum_line_state_size, "dense indexed and reserved totals differ");

    uint32_t item_size;
    require(tunnelchainTryComputeLineItemSize(offset, &item_size), "dense line item size failed");
    require(item_size % kCpuLineCacheSize == 0, "complete line item is not cache rounded");
    require(item_size >= sizeof(line_t) + offset && item_size - sizeof(line_t) - offset < kCpuLineCacheSize,
            "complete line has excessive or insufficient terminal padding");

    master_pool_t *master = masterpoolCreateWithCapacity(4);
    require(master != NULL, "failed to create dense master pool");
    generic_pool_t *pools[] = {genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(master, item_size, 2)};
    require(pools[0] != NULL, "failed to create dense line pool");

    // This fixture creates and owns normal lines. Exercise recycling as well as first allocation.
    for (unsigned int iteration = 0; iteration < 3; ++iteration)
    {
        line_t *line = lineCreateForWorker(0, pools, 0);
        require((uintptr_t) line % kCpuLineCacheSize == 0, "line allocation is not cache aligned");
        uint8_t *states = (uint8_t *) line->tunnels_line_state;
        for (size_t byte = 0; byte < item_size - sizeof(line_t); ++byte)
        {
            require(states[byte] == 0, "line creation left state or terminal padding dirty");
        }

        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
        {
            void *state = lineGetState(line, tunnels[i]);
            require((uintptr_t) state % 32 == 0, "line-state pointer is not 32-byte aligned");
            memorySet(state, 0xA5, reserved[i]);
        }
        require((uintptr_t) lineGetState(line, tunnels[2]) % kCpuLineCacheSize == 32,
                "fixture did not exercise a state inside a cache line");

        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
        {
            memoryZeroAligned32(lineGetState(line, tunnels[i]), tunnelGetCorrectAlignedLineStateSize(sizes[i]));
            const size_t cleared = tunnels[i]->lstate_offset + reserved[i];
            for (size_t byte = 0; byte < item_size - sizeof(line_t); ++byte)
            {
                const uint8_t expected = byte >= cleared && byte < offset ? 0xA5 : 0;
                require(states[byte] == expected, "line-state clearing crossed a slot boundary");
            }
            require(lineIsAlive(line) && lineGetWID(line) == 0, "slot clearing damaged the line header");
        }
        lineDestroy(line);
        require(masterpoolGetCheckedOut(master) == 0, "dense line was not returned to its pool");
    }

    genericpoolDestroy(pools[0]);
    masterpoolMakeEmpty(master);
    masterpoolDestroy(master);
    tunnelchainDestroy(chain);
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
    {
        tunnelDestroy(tunnels[i]);
    }
}

static void testSizeLimits(void)
{
    uint32_t       value          = 123;
    const uint32_t max_line_state = UINT32_MAX - 31U;
    require(tunnelTryAlignLineStateSize(max_line_state, &value) && value == max_line_state,
            "largest line-state size was rejected");
    value = 123;
    require(! tunnelTryAlignLineStateSize((size_t) max_line_state + 1U, &value) && value == 123,
            "line-state overflow changed its output");
    require(! tunnelTryAlignLineStateSize(SIZE_MAX, &value), "size_t line-state overflow was accepted");
    require(! tunnelTryAlignLineStateSize(0, NULL), "null line-state output was accepted");
    require(tunnelCreate(NULL, 0, UINT32_MAX) == NULL, "constructor accepted line-state alignment overflow");
    require(tunnelCreate(NULL, UINT32_MAX, 0) == NULL, "constructor accepted tunnel-state alignment overflow");

    const uint64_t allocator_limit = min((uint64_t) UINT32_MAX, (uint64_t) SIZE_MAX - kCpuLineCacheSize);
    const uint32_t max_item        = (uint32_t) (allocator_limit & ~((uint64_t) kCpuLineCacheSize - 1U));
    const uint32_t max_aggregate   = max_item - (uint32_t) sizeof(line_t);
    require(tunnelchainTryComputeLineItemSize(max_aggregate, &value) && value == max_item,
            "largest representable complete line item was rejected");
    value = 123;
    require(! tunnelchainTryComputeLineItemSize(max_aggregate + 1U, &value) && value == 123,
            "complete line rounding or allocator overhead overflow was accepted");
    require(! tunnelchainTryComputeLineItemSize(UINT32_MAX, &value), "complete line header overflow was accepted");
    require(! tunnelchainTryComputeLineItemSize(0, NULL), "null line-item output was accepted");
    require(tunnelchainTryComputeLineItemSize(32, &value) && value == sizeof(line_t) + kCpuLineCacheSize,
            "single short slot did not preserve the complete line boundary");
}

int main(void)
{
    testLargeOffsets();
    testDenseSlots();
    testSizeLimits();
    return 0;
}
