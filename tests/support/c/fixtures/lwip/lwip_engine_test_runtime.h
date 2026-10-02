/*
 * Covers: lwip engine test runtime; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Opt-in fixture/header composition. The including suite owns setup, case publication, and cleanup;
 * this header has no independent CTest entry.
 * Cases: the explicit main/fixture operations and boundary vectors below
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network or
 * application-throughput behavior.
 * CTest: owning suite registration in tests/cmake/native/; this is a helper/conditional source, not a
 * separate selectable test
 */
#pragma once

#include "engine.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "test_assert.h"
#include "trusted_checksum.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Suite-owned abort() preserves its original failure boundary. */
#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! TEST_CHECK(x, "requirement failed"))                                                                     \
        {                                                                                                              \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

static _Thread_local unsigned              owner = 255;
static _Thread_local const struct wloop_s *owner_loop;
static atomic_uint                         clock_ms;
static atomic_uint                         random_state = 100;

bool wwLwipEngineOwnerIsCurrent(uint8_t wid, const struct wloop_s *loop)
{
    return wid == owner && loop == owner_loop;
}

u32_t __wrap_sys_now(void)
{
    return atomic_load(&clock_ms);
}
unsigned int lwip_port_rand(void)
{
    return atomic_fetch_add(&random_state, 13);
}
u32_t wwLwipTcpIsn(const ip_addr_t *local, u16_t lp, const ip_addr_t *remote, u16_t rp)
{
    (void) local;
    (void) lp;
    (void) remote;
    (void) rp;
    return 1000 + owner;
}
uint16_t wwLwipChecksum(const void *data, int length)
{
    const uint8_t *bytes = data;
    uint32_t       sum   = 0;
    while (length > 1)
    {
        sum += ((unsigned) bytes[0] << 8) | bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += (unsigned) bytes[0] << 8;
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return lwip_htons((uint16_t) sum);
}

void wwMemoryCopyLarge(void *dest, const void *src, intmax_t length)
{
    memcpy(dest, src, (size_t) length);
}

void lwip_example_app_platform_assert(const char *message, int line, const char *file)
{
    fprintf(stderr, "%s:%d: lwIP: %s\n", file, line, message);
    abort();
}
