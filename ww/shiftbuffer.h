#pragma once

#include "ww.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*

    This is just a buffer, with parameters like length, cap
    cap means the space you can still use without any cost (its preallocated space)


    This buffer is supposed to be taken out of a pool (buffer_pool.h)
    and some of the other useful functions are defined there


*/

struct shift_buffer_s
{
    uint32_t curpos;
    uint32_t len;
    uint32_t capacity;
    uint16_t l_pad;
    uint16_t r_pad;
    //----------- 16 -----------
    uint8_t buf[];
};

typedef struct shift_buffer_s shift_buffer_t;

void            destroyShiftBuffer(shift_buffer_t *b);
shift_buffer_t *newShiftBufferWithPad(uint32_t minimum_capacity, uint16_t pad_left, uint16_t pad_right);
shift_buffer_t *newShiftBuffer(uint32_t minimum_capacity);
shift_buffer_t *concatBuffer(shift_buffer_t *restrict root, const shift_buffer_t *restrict buf);
shift_buffer_t *sliceBufferTo(shift_buffer_t *restrict dest, shift_buffer_t *restrict source, uint32_t bytes);
shift_buffer_t *sliceBuffer(shift_buffer_t *b, uint32_t bytes);
shift_buffer_t *duplicateBuffer(shift_buffer_t *b);

static inline uint32_t bufCap(shift_buffer_t *const b)
{
    return b->capacity;
}

static inline uint32_t bufCapNoPadding(shift_buffer_t *const b)
{
    assert(((uint32_t) b->l_pad + (uint32_t) b->r_pad) >= b->capacity);

    return b->capacity - ((uint32_t) b->l_pad + (uint32_t) b->r_pad);
}

// caps mean how much memory we own to be able to shift left/right
static inline uint32_t lCap(shift_buffer_t *const b)
{
    return b->curpos;
}

static inline uint32_t lCapNoPadding(shift_buffer_t *const b)
{
    return b->curpos - b->l_pad;
}

static inline uint32_t rCap(shift_buffer_t *const b)
{
    return (b->capacity - b->curpos);
}

static inline uint32_t rCapNoPadding(shift_buffer_t *const b)
{
    return b->capacity - (b->r_pad + b->curpos);
}

static inline void shiftl(shift_buffer_t *const b, const uint32_t bytes)
{

    assert(lCap(b) >= bytes);

    b->curpos -= bytes;
    b->len += bytes;
}

static inline void shiftr(shift_buffer_t *const b, const uint32_t bytes)
{
    assert(rCap(b) >= bytes);

    b->curpos += bytes;
    b->len -= bytes;
}

// developer should call this function or reserve function before writing
static inline void setLen(shift_buffer_t *const b, const uint32_t bytes)
{
    assert(rCap(b) >= bytes);
    b->len = bytes;
}

static inline uint32_t bufLen(const shift_buffer_t *const b)
{
    return b->len;
}

static inline void consume(shift_buffer_t *const b, const uint32_t bytes)
{
    setLen(b, bufLen(b) - bytes);
}

static inline const void *rawBuf(const shift_buffer_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

static inline unsigned char *rawBufMut(const shift_buffer_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

static inline void readRaw(const shift_buffer_t *const b, void *const dest, const uint32_t byte)
{
    memcpy(dest, rawBuf(b), byte);
}

static inline void writeRaw(shift_buffer_t *restrict const b, const void *restrict const buffer, const uint32_t len)
{
    memcpy(rawBufMut(b), buffer, len);
}

// UnAligned

static inline void readUnAlignedUI8(const shift_buffer_t *const b, uint8_t *const dest)
{
    memcpy(dest, rawBuf(b), sizeof(*dest));
}

static inline void readUnAlignedUI16(const shift_buffer_t *const b, uint16_t *const dest)
{
    memcpy(dest, rawBuf(b), sizeof(*dest));
}

static inline void readUnAlignedUI64(const shift_buffer_t *const b, uint64_t *const dest)
{
    memcpy(dest, rawBuf(b), sizeof(*dest));
}

static inline void writeUnAlignedI32(shift_buffer_t *const b, const int32_t data)
{
    memcpy(rawBufMut(b), &data, sizeof(data));
}

static inline void writeUnAlignedUI32(shift_buffer_t *const b, const uint32_t data)
{
    memcpy(rawBufMut(b), &data, sizeof(data));
}

static inline void writeUnAlignedI16(shift_buffer_t *const b, const int16_t data)
{
    memcpy(rawBufMut(b), &data, sizeof(data));
}

static inline void writeUnAlignedUI16(shift_buffer_t *const b, const uint16_t data)
{
    memcpy(rawBufMut(b), &data, sizeof(data));
}

static inline void writeUnAlignedUI8(shift_buffer_t *const b, const uint8_t data)
{
    memcpy(rawBufMut(b), &data, sizeof(data));
}

// Aligned

static inline void readUI8(const shift_buffer_t *const b, uint8_t *const dest)
{
    *dest = *(uint8_t *) rawBuf(b);
}

static inline void readUI16(const shift_buffer_t *const b, uint16_t *const dest)
{
    *dest = *(uint16_t *) rawBuf(b);
}

static inline void readUI64(const shift_buffer_t *const b, uint64_t *const dest)
{
    *dest = *(uint64_t *) rawBuf(b);
}

static inline void writeI32(shift_buffer_t *const b, const int32_t data)
{
    *(int32_t *) rawBufMut(b) = data;
}

static inline void writeUI32(shift_buffer_t *const b, const uint32_t data)
{
    *(uint32_t *) rawBufMut(b) = data;
}

static inline void writeI16(shift_buffer_t *const b, const int16_t data)
{
    *(int16_t *) rawBufMut(b) = data;
}

static inline void writeUI16(shift_buffer_t *const b, const uint16_t data)
{
    *(uint16_t *) rawBufMut(b) = data;
}

static inline void copyBuf(shift_buffer_t *restrict const to, shift_buffer_t *restrict const from, uint32_t length)
{
    assert(rCap(to) >= length);

    if (rCap(to) - length >= 128 && rCap(from) >= 128)
    {
        memCopy128(rawBufMut(to), rawBuf(from), length);
    }
    else
    {
        memcpy(rawBufMut(to), rawBuf(from), length);
    }
}

static inline shift_buffer_t *reserveBufSpace(shift_buffer_t *const b, const uint32_t bytes)
{
    if (rCap(b) < bytes)
    {
        shift_buffer_t *bigger_buf = newShiftBuffer(bufLen(b) + bytes);
        setLen(bigger_buf, bufLen(b));
        copyBuf(bigger_buf, b, bufLen(b));
        destroyShiftBuffer(b);
        return bigger_buf;
    }
    return b;
}

static inline void concatBufferNoCheck(shift_buffer_t *restrict root, const shift_buffer_t *restrict buf)
{
    uint32_t root_length   = bufLen(root);
    uint32_t append_length = bufLen(buf);
    setLen(root, root_length + append_length);
    memcpy(rawBufMut(root) + root_length, rawBuf(buf), append_length);
}

#ifdef DEBUG

// free and re create the buffer so in case of use after free we catch it
static shift_buffer_t *debugBufferWontBeReused(shift_buffer_t *b)
{
    shift_buffer_t *nbuf = duplicateBuffer(b);
    destroyShiftBuffer(b);
    return nbuf;
}

#define BUFFER_WONT_BE_REUSED(x) x = debugBufferWontBeReused(x)

#else

#define BUFFER_WONT_BE_REUSED(x)

#endif
