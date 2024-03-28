#include "buffer_pool.h"
#include <assert.h> // for assert
#include <malloc.h>
#include <string.h>
#ifdef DEBUG
#include "loggers/network_logger.h"
#endif

#define GBD_MAX_CAP 1024
#define DEFAULT_BUFFER_SIZE 4096

#undef max
#undef min
static inline size_t max(size_t x, size_t y) { return (((x) < (y)) ? (y) : (x)); }
static inline size_t min(size_t x, size_t y) { return (((x) < (y)) ? (x) : (y)); }

static void firstCharge(buffer_pool_t *state)
{
    // state->chunks = 1;
    state->available = malloc(2 * GBD_MAX_CAP * sizeof(shift_buffer_t *));

    for (size_t i = 0; i < GBD_MAX_CAP; i++)
    {
        state->available[i] = newShiftBuffer(DEFAULT_BUFFER_SIZE);
    }
    state->len = GBD_MAX_CAP;
}

static void reCharge(buffer_pool_t *state)
{

    const size_t increase = min((2 * GBD_MAX_CAP - state->len), GBD_MAX_CAP);
    for (size_t i = state->len; i < (state->len + increase); i++)
    {
        state->available[i] = newShiftBuffer(DEFAULT_BUFFER_SIZE);
    }
    state->len += increase;
#ifdef DEBUG
    LOGD("BufferPool: allocated %d new buffers, %zu are in use", increase, state->in_use);
#endif
}

static void giveMemBackToOs(buffer_pool_t *state)
{
    const size_t decrease = min(state->len, GBD_MAX_CAP);

    for (size_t i = state->len - decrease; i < state->len; i++)
    {
        destroyShiftBuffer(state->available[i]);
    }
    state->len -= decrease;

#ifdef DEBUG
    LOGD("BufferPool: freed %d buffers, %zu are in use", decrease, state->in_use);
#endif

    malloc_trim(0); //y tho?
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

#ifdef DEBUG
    state->in_use += 1;
#endif
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
#ifdef DEBUG
    state->in_use -= 1;
#endif
    reset(b);
    state->available[state->len] = b;
    ++(state->len);
    if (state->len > GBD_MAX_CAP + (GBD_MAX_CAP / 2))
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
#ifdef DEBUG
    state->in_use = 0;
#endif
    firstCharge(state);
    return state;
}
