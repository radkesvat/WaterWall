#pragma once

#include "global_state.h"
#include "wevent.h"

typedef struct test_wio_fd_pool_s
{
    master_pool_t  *master;
    master_pool_t  *saved_master;
    generic_pool_t *pool;
} test_wio_fd_pool_t;

static inline void testWioFdPoolSetup(test_wio_fd_pool_t *fixture)
{
    fixture->saved_master = GSTATE.masterpool_wio_fds;
    fixture->master       = masterpoolCreateWithCapacity(16);
    fixture->pool         = wiofdCreatePool(fixture->master, 8);
    if (fixture->master == NULL || fixture->pool == NULL)
    {
        fprintf(stderr, "failed to create the test WIO descriptor pool\n");
        exit(1);
    }
    GSTATE.masterpool_wio_fds = fixture->master;
}

static inline void testWioFdPoolTeardown(test_wio_fd_pool_t *fixture)
{
    GSTATE.masterpool_wio_fds = fixture->saved_master;
    genericpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->master);
    masterpoolDestroy(fixture->master);
    fixture->master = NULL;
    fixture->pool   = NULL;
}
