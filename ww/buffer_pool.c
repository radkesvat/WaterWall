#include "buffer_pool.h"
#include <assert.h> // for assert
#include <malloc.h>
#include <string.h>
#ifdef DEBUG
#include "loggers/network_logger.h"
#endif

#define LOW_MEMORY     0 // no preallocation (very small)
#define MED1_MEMORY    1 // APPROX 10MB per thread
#define MED2_MEMORY    2 // APPROX 20MB per thread
#define HIG1_MEMORY    3 // APPROX 28MB per thread
#define HIG2_MEMORY    4 // APPROX 36MB per thread
#define MEMORY_PROFILE HIG2_MEMORY

#define EVP_READ_BUFSIZE         (1U << 15) // 32K
#define BUFFERPOOL_CONTAINER_LEN (50 + (250 * MEMORY_PROFILE))
#define BUFFER_SIZE              ((MEMORY_PROFILE < MED2_MEMORY) ? 0 : EVP_READ_BUFSIZE)

#undef max
#undef min
static inline size_t max(size_t x, size_t y)
{
    return (((x) < (y)) ? (y) : (x));
}
static inline size_t min(size_t x, size_t y)
{
    return (((x) < (y)) ? (x) : (y));
}

static void firstCharge(buffer_pool_t *state)
{
    // state->chunks = 1;
    state->available = malloc(2 * BUFFERPOOL_CONTAINER_LEN * sizeof(shift_buffer_t *));

    for (size_t i = 0; i < BUFFERPOOL_CONTAINER_LEN; i++)
    {
        state->available[i] = newShiftBuffer(BUFFER_SIZE);
    }
    state->len = BUFFERPOOL_CONTAINER_LEN;
}

static void reCharge(buffer_pool_t *state)
{
    const size_t increase = min((2 * BUFFERPOOL_CONTAINER_LEN - state->len), BUFFERPOOL_CONTAINER_LEN);
    for (size_t i = state->len; i < (state->len + increase); i++)
    {
        state->available[i] = newShiftBuffer(BUFFER_SIZE);
    }
    state->len += increase;
#ifdef DEBUG
    LOGD("BufferPool: allocated %d new buffers, %zu are in use", increase, state->in_use);
#endif
}

static void giveMemBackToOs(buffer_pool_t *state)
{
    const size_t decrease = min(state->len, BUFFERPOOL_CONTAINER_LEN);

    for (size_t i = state->len - decrease; i < state->len; i++)
    {
        destroyShiftBuffer(state->available[i]);
    }
    state->len -= decrease;

#ifdef DEBUG
    LOGD("BufferPool: freed %d buffers, %zu are in use", decrease, state->in_use);
#endif

    malloc_trim(0); // y tho?
}

shift_buffer_t *popBuffer(buffer_pool_t *state)
{
    // return newShiftBuffer(BUFFER_SIZE);
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
    reset(b, BUFFER_SIZE);
    state->available[state->len] = b;
    ++(state->len);
    if (state->len > BUFFERPOOL_CONTAINER_LEN + (BUFFERPOOL_CONTAINER_LEN / 2))
    {
        giveMemBackToOs(state);
    }
}

buffer_pool_t *createBufferPool()
{
    buffer_pool_t *state = malloc(sizeof(buffer_pool_t));
    memset(state, 0, sizeof(buffer_pool_t));

    state->available = 0;
    state->len       = 0;
#ifdef DEBUG
    state->in_use = 0;
#endif
    firstCharge(state);
    return state;
}
