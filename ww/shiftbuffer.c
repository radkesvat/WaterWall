#include "shiftbuffer.h"
#include "managers/memory_manager.h"
#include "utils/mathutils.h"
#include "ww.h"
#include <assert.h> // for assert
#include <math.h>   //cel,log2,pow
#include <stdint.h>
#include <string.h>

// #define LEFTPADDING  ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 10) : (1U << 8)) - (sizeof(uint32_t) * 3))
// #define RIGHTPADDING ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 9) : (1U << 7)))

// #define TOTALPADDING ((uint32_t) (sizeof(shift_buffer_t) + (LEFTPADDING + RIGHTPADDING)))

void destroyShiftBuffer(shift_buffer_t *b)
{
    memoryFree(b);
}

shift_buffer_t *newShiftBufferWithPad(uint32_t minimum_capacity, uint16_t pad_left, uint16_t pad_right)
{
    if (minimum_capacity != 0 && minimum_capacity % kCpuLineCacheSize != 0)
    {
        minimum_capacity = (max(kCpuLineCacheSize, minimum_capacity) + kCpuLineCacheSizeMin1) & ~kCpuLineCacheSizeMin1;
    }

    uint32_t        real_cap = minimum_capacity + pad_left + pad_right;
    shift_buffer_t *b        = memoryAllocate(real_cap);

    b->len      = 0;
    b->curpos   = pad_left;
    b->capacity = real_cap;
    b->l_pad    = pad_left;
    b->r_pad    = pad_right;

    return b;
}

shift_buffer_t *newShiftBuffer(uint32_t minimum_capacity)
{
    return newShiftBufferWithPad(minimum_capacity, 0, 0);
}

shift_buffer_t *duplicateBuffer(shift_buffer_t *b)
{
    shift_buffer_t *newbuf = newShiftBufferWithPad(bufCapNoPadding(b), b->l_pad, b->r_pad);
    setLen(newbuf, bufLen(b));
    memoryCopy128(rawBufMut(newbuf), rawBuf(b), bufLen(b));
    return newbuf;
}

shift_buffer_t *concatBuffer(shift_buffer_t *restrict root, const shift_buffer_t *restrict const buf)
{
    uint32_t root_length   = bufLen(root);
    uint32_t append_length = bufLen(buf);
    root                   = reserveBufSpace(root, root_length + append_length);
    setLen(root, root_length + append_length);

    if (rCap(root) - append_length >= 128 && rCap(buf) >= 128)
    {
        memoryCopy128(rawBufMut(root) + root_length, rawBuf(buf), append_length);
    }
    else
    {
        memcpy(rawBufMut(root) + root_length, rawBuf(buf), append_length);
    }

    memcpy(rawBufMut(root) + root_length, rawBuf(buf), append_length);
    return root;
}

shift_buffer_t *sliceBufferTo(shift_buffer_t *restrict dest, shift_buffer_t *restrict source, const uint32_t bytes)
{
    assert(bytes <= bufLen(source));
    assert(bufLen(dest) == 0);

    dest = reserveBufSpace(dest, bytes);
    setLen(dest, bytes);

    copyBuf(dest, source, bytes);

    shiftr(source, bytes);

    return dest;
}

shift_buffer_t *sliceBuffer(shift_buffer_t *const b, const uint32_t bytes)
{
    shift_buffer_t *newbuf = newShiftBufferWithPad(bufCapNoPadding(b), b->l_pad, b->r_pad);
    sliceBufferTo(newbuf, b, bytes);
    return newbuf;
}
