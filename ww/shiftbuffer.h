#pragma once

#include "ww.h"
#include "generic_pool.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h> // memmove,memcpy

/*

    This is just a buffer, with parameters like length, cap
    cap means the space you can still use without any cost (its preallocated space)

    also, this buffer provides shallow copies ( simply think of it as a pointer duplicate )
    but, both of them can be destroyed and if a buffer has 0 owner, it will be freed

    shallow functions are never used by ww, the only user of those are the final developer
    who knows what they are doing

    if you want to use shallow copies, you can also use constrain functions to make sure
    those buffers do not overflow to each other and each will allocate their own buffer before expanding

    non shallow slice/other functions use calculated minimal copy or buffer swapping

    This buffer is supposed to be taken out of a pool (buffer_pool.h)
    and some of the other useful functions are defined there


*/

typedef unsigned int shiftbuffer_refc_t;

struct shift_buffer_s
{
    char               *pbuf;
    shiftbuffer_refc_t *refc;
    unsigned int        calc_len;
    unsigned int        curpos;
    unsigned int        full_cap;
    unsigned int        offset;
};

typedef struct shift_buffer_s shift_buffer_t;

void *allocShiftBufferPoolHandle(generic_pool_t *pool);
void  destroyShiftBufferPoolHandle(generic_pool_t *pool, void *item);

shift_buffer_t *newShiftBuffer(generic_pool_t *pool, unsigned int pre_cap);
shift_buffer_t *newShallowShiftBuffer(generic_pool_t *pool, shift_buffer_t *owner);
void            destroyShiftBuffer(generic_pool_t *pool, shift_buffer_t *self);
void            reset(shift_buffer_t *self, unsigned int cap);
void            unShallow(shift_buffer_t *self);
void            expand(shift_buffer_t *self, unsigned int increase);
void            concatBuffer(shift_buffer_t *restrict root, const shift_buffer_t *restrict buf);
void            sliceBufferTo(shift_buffer_t *restrict dest, shift_buffer_t *restrict source, unsigned int bytes);
shift_buffer_t *sliceBuffer(generic_pool_t *pool, shift_buffer_t *self, unsigned int bytes);
shift_buffer_t *shallowSliceBuffer(generic_pool_t *pool, shift_buffer_t *self, unsigned int bytes);

static inline bool isShallow(shift_buffer_t *self)
{
    return (*(self->refc) > 1);
}

static inline unsigned int bufCap(shift_buffer_t *const self)
{
    return self->full_cap + self->offset;
}

// caps mean how much memory we own to be able to shift left/right
static inline unsigned int lCap(shift_buffer_t *const self)
{
    return self->curpos;
}

static inline unsigned int rCap(shift_buffer_t *const self)
{
    return (self->full_cap - self->curpos);
}

static inline void constrainRight(shift_buffer_t *const self)
{
    self->full_cap = self->curpos + self->calc_len;
}

static inline void constrainLeft(shift_buffer_t *const self)
{
    self->offset += self->curpos;
    self->pbuf += self->curpos;
    self->full_cap -= self->curpos;
    self->curpos = 0;
}

static inline void shiftl(shift_buffer_t *const self, const unsigned int bytes)
{
begin:;
    if (lCap(self) < bytes)
    {
        if (! isShallow(self) && self->offset != 0)
        {
            self->curpos += self->offset;
            self->pbuf -= self->offset;
            self->full_cap += self->offset;
            self->offset = 0;
            // shiftl(self, bytes);
            goto begin;
        }
        expand(self, (bytes - lCap(self)));
    }

    self->curpos -= bytes;
    self->calc_len += bytes;
}

static inline void shiftr(shift_buffer_t *const self, const unsigned int bytes)
{
    // caller knows if there is space or not, checking here makes no sense
    self->curpos += bytes;
    self->calc_len -= bytes;
}

// developer should call this function or reserve function before writing
static inline void setLen(shift_buffer_t *const self, const unsigned int bytes)
{
    if (rCap(self) < bytes)
    {
        expand(self, (bytes - rCap(self)));
    }

    self->calc_len = bytes;
}

static inline unsigned int bufLen(const shift_buffer_t *const self)
{
    // return self->lenpos - self->curpos;
    return self->calc_len;
}

static inline void reserveBufSpace(shift_buffer_t *const self, const unsigned int bytes)
{
    if (rCap(self) < bytes)
    {
        expand(self, (bytes - rCap(self)));
    }
}

static inline void consume(shift_buffer_t *const self, const unsigned int bytes)
{
    setLen(self, bufLen(self) - bytes);
}

static inline const void *rawBuf(const shift_buffer_t *const self)
{
    return (void *) &(self->pbuf[self->curpos]);
}

static inline void readRaw(const shift_buffer_t *const self, void *const dest, const unsigned int byte)
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
    return (void *) &(self->pbuf[self->curpos]);
}

static inline void writeRaw(shift_buffer_t *restrict const self, const void *restrict const buffer,
                            const unsigned int len)
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
