#include <assert.h> // for assert
#include <stdlib.h>
#include "hv/hlog.h"
#include "buffer_dispatcher.h"

#define GBD_MAX_CAP 1024
#define DEFAULT_BUFFER_SIZE 4096

struct buffer_dispatcher_storage_s global_bd_storage;

static void reCharge()
{
    int count = GBD_MAX_CAP - global_bd_storage.len;
    global_bd_storage.chunks += 1;
    global_bd_storage.available = realloc(global_bd_storage.available, global_bd_storage.chunks * (GBD_MAX_CAP * sizeof(shift_buffer_t *)));

    for (size_t i = global_bd_storage.len; i < global_bd_storage.len + count; i++)
    {
        global_bd_storage.available[i] = newShiftBuffer(DEFAULT_BUFFER_SIZE);
    }
    global_bd_storage.len += count;
    hlogw("Global Buffer Dispatcher allocated %d new buffers, %zu are in use", count, global_bd_storage.in_use);
}
static void giveMemBackToOs()
{
    assert(global_bd_storage.len > GBD_MAX_CAP);
    global_bd_storage.chunks -= 1;

    for (size_t i = global_bd_storage.len - GBD_MAX_CAP; i < global_bd_storage.len; i++)
    {
        destroyShiftBuffer(global_bd_storage.available[i]);
    }
    global_bd_storage.len -= GBD_MAX_CAP;

    global_bd_storage.available = realloc(global_bd_storage.available, global_bd_storage.chunks * (GBD_MAX_CAP * sizeof(shift_buffer_t *)));
    hlogw("Global Buffer Dispatcher freed %d buffers, %zu are in use", GBD_MAX_CAP, global_bd_storage.in_use);
    // TODO: call malloc_trim
}

shift_buffer_t *popShiftBuffer()
{
    if (global_bd_storage.len <= 0)
    {
        reCharge();
    }
    --global_bd_storage.len;
    shift_buffer_t *result = global_bd_storage.available[global_bd_storage.len];

    ++global_bd_storage.in_use;
    return result;
}

void reuseShiftBuffer(shift_buffer_t *b)
{
    if (b->shadowed)
    {
        free(b);
        return;
    }
    --global_bd_storage.in_use;
    ++global_bd_storage.len;
    if (global_bd_storage.len > GBD_MAX_CAP)
    {
        giveMemBackToOs();
    }
}

void initGBD()
{
    global_bd_storage.available = malloc(1);
    global_bd_storage.len = 0;
    global_bd_storage.in_use = 0;
    global_bd_storage.chunks = 0;
    reCharge();
}
