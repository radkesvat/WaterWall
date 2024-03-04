#include <assert.h> // for assert
#include <stdlib.h>
#include "loggers/network_logger.h"
#include "buffer_pool.h"

#define GBD_MAX_CAP 1024
#define DEFAULT_BUFFER_SIZE 4096

static void firstCharge(buffer_pool_t *state)
{
    int count = GBD_MAX_CAP;
    state->chunks += 1;
    state->available = malloc(state->chunks * (GBD_MAX_CAP * sizeof(shift_buffer_t *)));

    for (size_t i = state->len; i < state->len + count; i++)
    {
        state->available[i] = newShiftBuffer(DEFAULT_BUFFER_SIZE);
    }
    state->len += count;
}

static void reCharge(buffer_pool_t *state)
{
    state->chunks += 1;
    state->available = realloc(state->available, state->chunks * (GBD_MAX_CAP * sizeof(shift_buffer_t *)));

    for (size_t i = state->len; i < state->len + GBD_MAX_CAP; i++)
    {
        state->available[i] = newShiftBuffer(DEFAULT_BUFFER_SIZE);
    }
    state->len += GBD_MAX_CAP;
#ifdef DEBUG
    LOGD("BufferPool allocated %d new buffers, %zu are in use", GBD_MAX_CAP, state->in_use);
#endif
}

static void giveMemBackToOs(buffer_pool_t *state)
{
    assert(state->len > GBD_MAX_CAP);
    state->chunks -= 1;

    for (size_t i = 0; i < GBD_MAX_CAP; i++)
    {
        destroyShiftBuffer(state->available[i]);
    }
    state->len -= GBD_MAX_CAP;

    state->available = realloc(state->available, state->chunks * (GBD_MAX_CAP * sizeof(shift_buffer_t *)));
    LOGD("BufferPool freed %d buffers, %zu are in use", GBD_MAX_CAP, state->in_use);
    // TODO: call malloc_trim
}

shift_buffer_t *popBuffer(buffer_pool_t *state)
{
    // return newShiftBuffer(DEFAULT_BUFFER_SIZE);
    if (state->len <= 0)
    {
        reCharge(state);
    }
    --(state->len);
    shift_buffer_t *result = state->available[state->len];

    ++(state->in_use);
    return result;
}

void reuseBuffer(buffer_pool_t *state, shift_buffer_t *b)
{
    // destroyShiftBuffer(b);
    // return;
    if (*(b->refc) > 1)
    {
        destroyShiftBuffer(b);
        return;
    }
    --(state->in_use);
    reset(b);
    state->available[state->len] = b;
    ++(state->len);
    if ((state->len) > GBD_MAX_CAP)
    {
        giveMemBackToOs(state);
    }
}

buffer_pool_t *createBufferPool()
{
    buffer_pool_t *state = malloc(sizeof(buffer_pool_t));
    memset(state, 0, sizeof(buffer_pool_t));

    state->available = 0;
    state->len = 0;
    state->in_use = 0;
    state->chunks = 0;
    firstCharge(state);
    return state;
}
