#include "shiftbuffer.h"
#include "utils/mathutils.h"
#include "ww.h"
#include <assert.h> // for assert
#include <math.h>   //cel,log2,pow
#include <stdint.h>
#include <string.h>

#define LEFTPADDING  (RAM_PROFILE >= kRamProfileS2Memory ? (1U << 10) : (1U << 8))
#define RIGHTPADDING ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 9) : (1U << 7)))

#define TOTALPADDING ((uint32_t) (sizeof(shift_buffer_t) + (LEFTPADDING + RIGHTPADDING)))

void destroyShiftBuffer(shift_buffer_t *self)
{
    globalFree(self);
}

shift_buffer_t *newShiftBuffer(uint32_t pre_cap) // NOLINT
{
    if (pre_cap != 0 && pre_cap % kCpuLineCacheSize != 0)
    {
        pre_cap = (max(kCpuLineCacheSize, pre_cap) + kCpuLineCacheSizeMin1) & ~kCpuLineCacheSizeMin1;
    }

    uint32_t        real_cap = pre_cap + TOTALPADDING;
    shift_buffer_t *self     = globalMalloc(real_cap);

    self->len      = 0;
    self->curpos   = LEFTPADDING;
    self->capacity = real_cap;

    return self;
}

// this function is made for internal use (most probably in bufferpool)
shift_buffer_t *reset(shift_buffer_t *self, uint32_t pre_cap)
{

    if (pre_cap != 0 && pre_cap % kCpuLineCacheSize != 0)
    {
        pre_cap = (max(kCpuLineCacheSize, pre_cap) + kCpuLineCacheSizeMin1) & ~kCpuLineCacheSizeMin1;
    }

    uint32_t real_cap = pre_cap + TOTALPADDING;

    if (self->capacity != real_cap)
    {
        destroyShiftBuffer(self);
        return newShiftBuffer(pre_cap);
    }

    self->len      = 0;
    self->curpos   = LEFTPADDING;
    self->capacity = real_cap;
    return self;
}

shift_buffer_t *duplicateBuffer(shift_buffer_t *b)
{
    uint32_t        pre_cap = bufCap(b) - TOTALPADDING;
    shift_buffer_t *newbuf  = newShiftBuffer(pre_cap);
    setLen(newbuf, bufLen(b));
    memcpy(rawBufMut(newbuf), rawBuf(b), bufLen(b));
    return newbuf;
}

shift_buffer_t *concatBuffer(shift_buffer_t *restrict root, const shift_buffer_t *restrict const buf)
{
    uint32_t root_length   = bufLen(root);
    uint32_t append_length = bufLen(buf);
    root                   = reserveBufSpace(root, root_length + append_length);
    setLen(root, root_length + append_length);
    memcpy(rawBufMut(root) + root_length, rawBuf(buf), append_length);
    return root;
}

shift_buffer_t *sliceBufferTo(shift_buffer_t *restrict dest, shift_buffer_t *restrict source, const uint32_t bytes)
{
    assert(bytes <= bufLen(source));
    assert(bufLen(dest) == 0);

    if (rCap(dest) < bytes)
    {
        shift_buffer_t *bigger_buf = newShiftBuffer(bytes);
        destroyShiftBuffer(dest);
        dest = bigger_buf;
    }
    setLen(dest, bytes);
    memcpy(rawBufMut(dest), rawBuf(source), bytes);
    shiftr(source, bytes);

    return dest;
}

shift_buffer_t *sliceBuffer(shift_buffer_t *const self, const uint32_t bytes)
{
    shift_buffer_t *newbuf = newShiftBuffer(self->capacity - TOTALPADDING);
    sliceBufferTo(newbuf, self, bytes);
    return newbuf;
}
