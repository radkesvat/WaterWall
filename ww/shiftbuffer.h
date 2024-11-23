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

#if defined(WW_AVX) && defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))

#define EXTRA_ALLOC  128
#define BUF_USES_AVX 1

#include <x86intrin.h>
static inline void memCopy128(void *dest, const void *src, long int n)
{
    __m256i       *d_vec = (__m256i *) (dest);
    const __m256i *s_vec = (const __m256i *) (src);

    if ((uintptr_t) dest % 128 != 0 || (uintptr_t) src % 128 != 0)
    {

        while (n > 0)
        {
            _mm256_storeu_si256(d_vec, _mm256_loadu_si256(s_vec));
            _mm256_storeu_si256(d_vec + 1, _mm256_loadu_si256(s_vec + 1));
            _mm256_storeu_si256(d_vec + 2, _mm256_loadu_si256(s_vec + 2));
            _mm256_storeu_si256(d_vec + 3, _mm256_loadu_si256(s_vec + 3));

            n -= 128;
            d_vec += 4;
            s_vec += 4;
        }

        return;
    }

    while (n > 0)
    {
        _mm256_store_si256(d_vec, _mm256_load_si256(s_vec));
        _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vec + 1));
        _mm256_store_si256(d_vec + 2, _mm256_load_si256(s_vec + 2));
        _mm256_store_si256(d_vec + 3, _mm256_load_si256(s_vec + 3));

        n -= 128;
        d_vec += 4;
        s_vec += 4;
    }
}

#else

#define EXTRA_ALLOC  0
#define BUF_USES_AVX 0

static inline void memCopy128(void *__restrict __dest, const void *__restrict __src, size_t __n)
{
    memcpy(__dest, __src, __n);
}

#endif

struct shift_buffer_s
{
    uint32_t len;
    uint32_t curpos;
    uint32_t capacity;
#if BUF_USES_AVX
    uint8_t _pad_[EXTRA_ALLOC];
#endif
    uint8_t buf[];
};

typedef struct shift_buffer_s shift_buffer_t;

shift_buffer_t *newShiftBuffer(uint32_t pre_cap);
void            destroyShiftBuffer(shift_buffer_t *self);
shift_buffer_t *reset(shift_buffer_t *self, uint32_t cap);
shift_buffer_t *concatBuffer(shift_buffer_t *restrict root, const shift_buffer_t *restrict buf);
shift_buffer_t *sliceBufferTo(shift_buffer_t *restrict dest, shift_buffer_t *restrict source, uint32_t bytes);
shift_buffer_t *sliceBuffer(shift_buffer_t *self, uint32_t bytes);
shift_buffer_t *duplicateBuffer(shift_buffer_t *b);

static inline unsigned int bufCap(shift_buffer_t *const self)
{
    return self->capacity;
}
// caps mean how much memory we own to be able to shift left/right
static inline uint32_t lCap(shift_buffer_t *const self)
{
    return self->curpos;
}

static inline uint32_t rCap(shift_buffer_t *const self)
{
    return (self->capacity - self->curpos);
}

static inline void shiftl(shift_buffer_t *const self, const uint32_t bytes)
{

    assert(lCap(self) >= bytes);

    self->curpos -= bytes;
    self->len += bytes;
}

static inline void shiftr(shift_buffer_t *const self, const uint32_t bytes)
{
    // caller knows if there is space or not, checking here makes no sense
    self->curpos += bytes;
    self->len -= bytes;
}

// developer should call this function or reserve function before writing
static inline void setLen(shift_buffer_t *const self, const uint32_t bytes)
{
    assert(rCap(self) >= bytes);
    self->len = bytes;
}

static inline uint32_t bufLen(const shift_buffer_t *const self)
{
    // return self->lenpos - self->curpos;
    return self->len;
}

static inline void consume(shift_buffer_t *const self, const uint32_t bytes)
{
    setLen(self, bufLen(self) - bytes);
}

static inline const void *rawBuf(const shift_buffer_t *const self)
{
    return (void *) &(self->buf[self->curpos]);
}

static inline void readRaw(const shift_buffer_t *const self, void *const dest, const uint32_t byte)
{
    memcpy(dest, rawBuf(self), byte);
}

static inline void readUI8(const shift_buffer_t *const self, uint8_t *const dest)
{
    // *dest = *(uint8_t *) rawBuf(self); address could be misaligned
    memcpy(dest, rawBuf(self), sizeof(*dest));
}

static inline void readUI16(const shift_buffer_t *const self, uint16_t *const dest)
{
    // *dest = *(uint16_t *) rawBuf(self); address could be misaligned
    memcpy(dest, rawBuf(self), sizeof(*dest));
}

static inline void readUI64(const shift_buffer_t *const self, uint64_t *const dest)
{

    // *dest = *(uint64_t *) rawBuf(self); address could be misaligned
    memcpy(dest, rawBuf(self), sizeof(*dest));
}

/*
    Call setLen/bufLen to know how much memory you own before any kind of writing
*/

static inline unsigned char *rawBufMut(const shift_buffer_t *const self)
{
    return (void *) &(self->buf[self->curpos]);
}

static inline void writeRaw(shift_buffer_t *restrict const self, const void *restrict const buffer, const uint32_t len)
{
    memcpy(rawBufMut(self), buffer, len);
}

static inline void writeI32(shift_buffer_t *const self, const int32_t data)
{
    // *(int32_t *) rawBufMut(self) = data; address could be misaligned
    memcpy(rawBufMut(self), &data, sizeof(data));
}

static inline void writeUI32(shift_buffer_t *const self, const uint32_t data)
{
    // *(uint32_t *) rawBufMut(self) = data; address could be misaligned
    memcpy(rawBufMut(self), &data, sizeof(data));
}

static inline void writeI16(shift_buffer_t *const self, const int16_t data)
{
    // *(int16_t *) rawBufMut(self) = data; address could be misaligned
    memcpy(rawBufMut(self), &data, sizeof(data));
}

static inline void writeUI16(shift_buffer_t *const self, const uint16_t data)
{
    // *(uint16_t *) rawBufMut(self) = data; address could be misaligned
    memcpy(rawBufMut(self), &data, sizeof(data));
}

static inline void writeUI8(shift_buffer_t *const self, const uint8_t data)
{
    // *(uint8_t *) rawBufMut(self) = data; address could be misaligned
    memcpy(rawBufMut(self), &data, sizeof(data));
}

static inline shift_buffer_t *reserveBufSpace(shift_buffer_t *const self, const uint32_t bytes)
{
    if (rCap(self) < bytes)
    {
        shift_buffer_t *bigger_buf = newShiftBuffer(bytes);
        setLen(bigger_buf, bufLen(self));
        memCopy128(rawBufMut(bigger_buf), rawBuf(self), bufLen(self));
        destroyShiftBuffer(self);
        return bigger_buf;
    }
    return self;
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
