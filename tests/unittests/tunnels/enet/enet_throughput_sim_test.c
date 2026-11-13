/* CTest: waterwall.enet_throughput_sim_unit.
 * Measures the throughput the ENet protocol allows over the simulated link in
 * enet_sim.h and prints one line per scenario. A sender keeps its queue full
 * until the receiver has 4 MiB. Assertions: throughput never exceeds ENet's
 * 64 KiB-per-round-trip window bound, and on a lossless link it reaches at
 * least half of that bound. The printed numbers are the measured values that
 * the node documentation quotes. No socket or wall clock is used. */

#include "enet_sim.h"

#include <inttypes.h>
#include <stdio.h>

enum
{
    kTransferBytes = 4 * 1024 * 1024,
    kWriteChunk    = 32768
};

typedef struct scenario_s
{
    uint32_t delay_ms; /* one-way; the round trip is twice this */
    uint32_t loss_permille;
} scenario_t;

static bool bothConnected(const sim_world_t *world)
{
    return world->end[0].connected_calls == 1 && world->end[1].connected_calls == 1;
}

static void runScenario(const scenario_t *scenario)
{
    sim_world_t                world;
    const enet_driver_config_t client = simConfig(kEnetDriverRoleClient);
    const enet_driver_config_t server = simConfig(kEnetDriverRoleServer);
    simOpen(&world, &client, &server, scenario->delay_ms);
    simRequire(simAdvanceUntil(&world, 5000, bothConnected), "handshake did not finish");
    world.loss_permille = scenario->loss_permille;

    uint8_t       *chunk    = simPattern(kWriteChunk, 1);
    const uint64_t started  = world.now;
    const uint64_t deadline = started + 1800000;
    size_t         written  = 0;
    while (world.end[1].stream_length < (size_t) kTransferBytes)
    {
        simRequire(world.now < deadline, "transfer did not finish in 30 virtual minutes");
        simRequire(world.end[0].closed_calls == 0 && world.end[1].closed_calls == 0,
                   "session closed during the transfer");
        while (written < (size_t) kTransferBytes && ! enetDriverSendHold(world.end[0].driver))
        {
            simRequire(simWrite(&world, 0, chunk, kWriteChunk), "write refused");
            written += kWriteChunk;
        }
        simStep(&world);
    }

    const uint64_t elapsed_ms = world.now - started;
    const uint64_t rate       = (uint64_t) kTransferBytes * 1000U / elapsed_ms;
    const uint64_t bound      = 65536ULL * 1000U / (2U * scenario->delay_ms);
    printf("enet_throughput rtt_ms=%" PRIu32 " loss_permille=%" PRIu32 " bytes=%d elapsed_ms=%" PRIu64
           " rate_bytes_per_s=%" PRIu64 " window_bound_bytes_per_s=%" PRIu64 " percent_of_bound=%" PRIu64 "\n",
           2U * scenario->delay_ms,
           scenario->loss_permille,
           (int) kTransferBytes,
           elapsed_ms,
           rate,
           bound,
           rate * 100U / bound);

    simRequire(rate <= bound + bound / 10U, "throughput exceeded the 64 KiB per round trip window bound");
    if (scenario->loss_permille == 0)
    {
        simRequire(rate >= bound / 2U, "lossless throughput fell below half of the window bound");
    }

    free(chunk);
    simDestroy(&world);
}

static void testThroughputAcrossScenarios(void)
{
    static const scenario_t scenarios[] = {
        {10, 0},
        {25, 0},
        {50, 0},
        {100, 0},
        {50, 10},
        {50, 50},
        {100, 10},
    };
    for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); ++i)
    {
        runScenario(&scenarios[i]);
    }
}

int main(void)
{
    TEST_RUN_CASE(testThroughputAcrossScenarios);
    return 0;
}
