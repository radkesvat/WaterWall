#include <assert.h> // for assert
#include <stdlib.h>
#include "hv/hlog.h"
#include "buffer_dispatcher.h"

#define GBD_MAX_CAP 1024
#define DEFAULT_BUFFER_SIZE 4096

static void reCharge(buffer_dispatcher_storage_t *state)
{
    int count = GBD_MAX_CAP - state->len;
    state->chunks += 1;
    state->available = realloc(state->available, state->chunks * (GBD_MAX_CAP * sizeof(shift_buffer_t *)));

    for (size_t i = state->len; i < state->len + count; i++)
    {
        state->available[i] = newShiftBuffer(DEFAULT_BUFFER_SIZE);
    }
    state->len += count;
    hlogw("Global Buffer Dispatcher allocated %d new buffers, %zu are in use", count, state->in_use);
}

static void giveMemBackToOs(buffer_dispatcher_storage_t *state)
{
    assert(state->len > GBD_MAX_CAP);
    state->chunks -= 1;

    for (size_t i = state->len - GBD_MAX_CAP; i < state->len; i++)
    {
        destroyShiftBuffer(state->available[i]);
    }
    state->len -= GBD_MAX_CAP;

    state->available = realloc(state->available, state->chunks * (GBD_MAX_CAP * sizeof(shift_buffer_t *)));
    hlogw("Global Buffer Dispatcher freed %d buffers, %zu are in use", GBD_MAX_CAP, state->in_use);
    // TODO: call malloc_trim
}

shift_buffer_t *popShiftBuffer(buffer_dispatcher_storage_t *state)
{
    if (state->len <= 0)
    {
        reCharge(state);
    }
    --state->len;
    shift_buffer_t *result = state->available[state->len];

    ++state->in_use;
    return result;
}

void reuseShiftBuffer(buffer_dispatcher_storage_t *state,shift_buffer_t *b)
{
    if (b->shadowed)
    {
        free(b);
        return;
    }
    --(state->in_use);
    ++(state->len);
    if ((state->len) > GBD_MAX_CAP)
    {
        giveMemBackToOs(state);
    }
}

buffer_dispatcher_storage_t *createBufferDispatcher()
{
    buffer_dispatcher_storage_t *state = malloc(sizeof(buffer_dispatcher_storage_t));
    memset(state, 0, sizeof(buffer_dispatcher_storage_t));

    state->available = malloc(1);
    state->len = 0;
    state->in_use = 0;
    state->chunks = 0;
    reCharge(state);
    return state;
}
