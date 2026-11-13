#pragma once

/*
 * Deterministic in-memory link between two ENet drivers, for unit tests.
 *
 * Time is virtual. simStep() advances one millisecond: it delivers the
 * datagrams that are due, then services each driver whose own next-service
 * delay has elapsed. Loss, duplication and jitter come from a fixed-seed
 * generator, so every run is identical. No socket or wall clock is involved.
 * End 0 is the client and end 1 is the server.
 */

#include "EnetCommon/driver.h"

#include "test_assert.h"

#include <stdlib.h>
#include <string.h>

#define simRequire(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kSimDatagramCapacity = 4096
};

typedef struct sim_datagram_s
{
    struct sim_datagram_s *next;
    uint64_t               deliver_at;
    int                    to;
    size_t                 length;
    uint8_t                data[kSimDatagramCapacity];
} sim_datagram_t;

struct sim_world_s;

typedef struct sim_end_s
{
    struct sim_world_s *world;
    int                 index;
    enet_driver_t      *driver;
    uint8_t            *stream; /* every byte the stream sink received, in order */
    size_t              stream_length;
    size_t              stream_capacity;
    size_t              stream_length_at_close;
    uint64_t            next_service_at;
    uint64_t            datagrams_sent;
    unsigned            connected_calls;
    unsigned            closed_calls;
    enet_driver_close_t close_reason;
} sim_end_t;

typedef struct sim_world_s
{
    uint64_t        now;
    uint32_t        delay_ms;  /* one-way latency */
    uint32_t        jitter_ms; /* extra random latency in [0, jitter_ms] */
    uint32_t        loss_permille;
    uint32_t        duplicate_permille;
    bool            cut; /* every datagram is lost */
    uint64_t        rng;
    sim_datagram_t *queue; /* sorted by deliver_at, first in first out among equals */
    uint8_t         lost[kSimDatagramCapacity];
    sim_end_t       end[2];
} sim_world_t;

typedef bool (*sim_predicate_t)(const sim_world_t *world);

static inline uint32_t simRandom(sim_world_t *world)
{
    world->rng ^= world->rng << 13;
    world->rng ^= world->rng >> 7;
    world->rng ^= world->rng << 17;
    return (uint32_t) (world->rng >> 32);
}

static inline bool simChance(sim_world_t *world, uint32_t permille)
{
    return permille != 0 && simRandom(world) % 1000U < permille;
}

static inline void simEnqueue(sim_world_t *world, sim_datagram_t *datagram)
{
    sim_datagram_t **slot = &world->queue;
    while (*slot != NULL && (*slot)->deliver_at <= datagram->deliver_at)
    {
        slot = &(*slot)->next;
    }
    datagram->next = *slot;
    *slot          = datagram;
}

static inline uint8_t *simDatagramSink(void *user, size_t length)
{
    sim_end_t   *end   = user;
    sim_world_t *world = end->world;
    simRequire(length <= kSimDatagramCapacity, "driver produced a datagram above the ENet maximum");
    end->datagrams_sent += 1;
    if (world->cut || simChance(world, world->loss_permille))
    {
        return world->lost; /* sent, but it never arrives */
    }
    sim_datagram_t *datagram = malloc(sizeof(*datagram));
    simRequire(datagram != NULL, "out of memory");
    datagram->to         = 1 - end->index;
    datagram->length     = length;
    datagram->deliver_at = world->now + world->delay_ms;
    if (world->jitter_ms != 0)
    {
        datagram->deliver_at += simRandom(world) % (world->jitter_ms + 1U);
    }
    simEnqueue(world, datagram);
    return datagram->data;
}

static inline void simStreamSink(void *user, const uint8_t *data, size_t length)
{
    sim_end_t *end = user;
    if (end->stream_length + length > end->stream_capacity)
    {
        size_t capacity = end->stream_capacity != 0 ? end->stream_capacity : 65536;
        while (capacity < end->stream_length + length)
        {
            capacity *= 2;
        }
        end->stream = realloc(end->stream, capacity);
        simRequire(end->stream != NULL, "out of memory");
        end->stream_capacity = capacity;
    }
    memcpy(end->stream + end->stream_length, data, length);
    end->stream_length += length;
}

static inline void simConnectedSink(void *user)
{
    sim_end_t *end = user;
    end->connected_calls += 1;
}

static inline void simClosedSink(void *user, enet_driver_close_t why)
{
    sim_end_t *end = user;
    end->closed_calls += 1;
    end->close_reason           = why;
    end->stream_length_at_close = end->stream_length;
}

static inline enet_driver_config_t simConfig(enet_driver_role_t role)
{
    const enet_driver_config_t config = {
        .role                 = role,
        .host_mtu             = 1472,
        .ping_interval_ms     = 10000,
        .no_recv_timeout_ms   = 30000,
        .send_buffer_limit    = 524288,
        .receive_buffer_limit = 1048576,
        .incoming_bandwidth   = 0,
        .outgoing_bandwidth   = 0,
        .random_seed          = role == kEnetDriverRoleClient ? 0x01234567U : 0x07654321U,
    };
    return config;
}

/* Recomputes when this end next needs a service call. Call it after every driver call on that end. */
static inline void simSchedule(sim_end_t *end)
{
    const uint32_t delay = enetDriverNextServiceDelayMs(end->driver, end->world->now);
    end->next_service_at = delay == ENET_DRIVER_NO_SERVICE ? UINT64_MAX : end->world->now + delay;
}

/* Creates both drivers on a clean link with the given one-way latency and sends the client's connect request. */
static inline void simOpen(sim_world_t *world, const enet_driver_config_t *client, const enet_driver_config_t *server,
                           uint32_t delay_ms)
{
    static const enet_driver_sinks_t sinks = {
        .datagram = simDatagramSink, .stream = simStreamSink, .connected = simConnectedSink, .closed = simClosedSink};
    simRequire(enetDriverInstall(malloc, free), "allocator install failed");
    memset(world, 0, sizeof(*world));
    world->now      = 1000;
    world->delay_ms = delay_ms;
    world->rng      = 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 2; ++i)
    {
        world->end[i].world = world;
        world->end[i].index = i;
    }
    world->end[0].driver = enetDriverCreate(client, &sinks, &world->end[0], world->now);
    world->end[1].driver = enetDriverCreate(server, &sinks, &world->end[1], world->now);
    simRequire(world->end[0].driver != NULL && world->end[1].driver != NULL, "driver creation failed");
    enetDriverService(world->end[0].driver, world->now);
    simSchedule(&world->end[0]);
    simSchedule(&world->end[1]);
}

static inline void simStep(sim_world_t *world)
{
    while (world->queue != NULL && world->queue->deliver_at <= world->now)
    {
        sim_datagram_t *datagram = world->queue;
        world->queue             = datagram->next;
        sim_end_t     *end       = &world->end[datagram->to];
        const unsigned copies    = simChance(world, world->duplicate_permille) ? 2U : 1U;
        for (unsigned i = 0; i < copies; ++i)
        {
            enetDriverInput(end->driver, datagram->data, datagram->length, world->now);
        }
        simSchedule(end);
        free(datagram);
    }
    for (int i = 0; i < 2; ++i)
    {
        sim_end_t *end = &world->end[i];
        if (end->next_service_at <= world->now)
        {
            enetDriverService(end->driver, world->now);
            simSchedule(end);
        }
    }
    world->now += 1;
}

static inline void simAdvance(sim_world_t *world, uint64_t milliseconds)
{
    const uint64_t until = world->now + milliseconds;
    while (world->now < until)
    {
        simStep(world);
    }
}

/* Advances until predicate holds or budget_ms of virtual time passed. Returns whether predicate holds. */
static inline bool simAdvanceUntil(sim_world_t *world, uint64_t budget_ms, sim_predicate_t predicate)
{
    const uint64_t until = world->now + budget_ms;
    while (! predicate(world) && world->now < until)
    {
        simStep(world);
    }
    return predicate(world);
}

static inline void simDestroy(sim_world_t *world)
{
    for (int i = 0; i < 2; ++i)
    {
        enetDriverDestroy(world->end[i].driver);
        free(world->end[i].stream);
    }
    while (world->queue != NULL)
    {
        sim_datagram_t *datagram = world->queue;
        world->queue             = datagram->next;
        free(datagram);
    }
}

/* Deterministic bytes for payload comparison. The caller frees the result. */
static inline uint8_t *simPattern(size_t length, uint32_t seed)
{
    uint8_t *bytes = malloc(length != 0 ? length : 1);
    simRequire(bytes != NULL, "out of memory");
    uint32_t state = seed;
    for (size_t i = 0; i < length; ++i)
    {
        state    = state * 1664525U + 1013904223U;
        bytes[i] = (uint8_t) (state >> 24);
    }
    return bytes;
}

/* Writes application bytes at one end and reschedules that end. */
static inline bool simWrite(sim_world_t *world, int index, const uint8_t *data, size_t length)
{
    sim_end_t *end      = &world->end[index];
    const bool accepted = enetDriverWrite(end->driver, data, length, world->now);
    simSchedule(end);
    return accepted;
}
