#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h> // free
#include <string.h> // memmove,memcpy

#if defined(DEBUG) && ! defined(hlog)
#include "loggers/network_logger.h" //some logs needs to be printed on debug mode
#endif

struct shift_buffer_s
{
    unsigned int  calc_len;
    unsigned int  lenpos;
    unsigned int  curpos;
    unsigned int  cap; // half of full cap
    unsigned int  full_cap;
    unsigned int *refc;
    char *        pbuf;
};
typedef struct shift_buffer_s shift_buffer_t;

shift_buffer_t *newShiftBuffer(unsigned int pre_cap);
shift_buffer_t *newShallowShiftBuffer(shift_buffer_t *owner);
void            destroyShiftBuffer(shift_buffer_t *self);
void            reset(shift_buffer_t *self, unsigned int cap);
void            unShallow(shift_buffer_t *self);
void            expand(shift_buffer_t *self, unsigned int increase);
void            appendBuffer(shift_buffer_t *restrict root, shift_buffer_t *restrict buf);

inline bool isShallow(shift_buffer_t *self)
{
    return (*(self->refc) > 1);
}
// caps mean how much memory we own to be able to shift left/right
inline unsigned int lCap(shift_buffer_t *self)
{
    return self->curpos;
}
inline unsigned int rCap(shift_buffer_t *self)
{
    return (self->full_cap - self->curpos);
}

inline void shiftl(shift_buffer_t *self, unsigned int bytes)
{
    if (lCap(self) < bytes)
    {
        expand(self, (bytes - lCap(self)));
    }
    else if (isShallow(self) && bytes > 0)
    {
        unShallow(self);
    }
    self->curpos -= bytes;
    self->calc_len += bytes;
}

inline void shiftr(shift_buffer_t *self, unsigned int bytes)
{
    // caller knows if there is space or not, checking here makes no sense
    self->curpos += bytes;
    self->calc_len -= bytes;
}

// caller must call this function to own the memory before writing
inline void setLen(shift_buffer_t *self, unsigned int bytes)
{
    if (rCap(self) < bytes)
    {
        expand(self, (bytes - rCap(self)));
    }
    else if (isShallow(self) && self->curpos + bytes > self->lenpos)
    {
        unShallow(self);
    }
    self->lenpos   = self->curpos + bytes;
    self->calc_len = bytes;
}

inline unsigned int bufLen(shift_buffer_t *self)
{
    // return self->lenpos - self->curpos;
    return self->calc_len;
}

// its only a hint, you are not allowed to write to that space before setLen
inline void reserveBufSpace(shift_buffer_t *self, unsigned int bytes)
{
    if (rCap(self) < bytes)
    {
        expand(self, (bytes - rCap(self)));
    }
}

inline void consume(shift_buffer_t *self, unsigned int bytes)
{
    setLen(self, bufLen(self) - bytes);
}

inline const void *rawBuf(shift_buffer_t *self)
{
    return (void *) &(self->pbuf[self->curpos]);
}
inline void readUI8(shift_buffer_t *self, uint8_t *dest)
{
    *dest = *(uint8_t *) rawBuf(self);
}
inline void readUI16(shift_buffer_t *self, uint16_t *dest)
{
    *dest = *(uint16_t *) rawBuf(self);
}
inline void readUI64(shift_buffer_t *self, uint64_t *dest)
{
    *dest = *(uint64_t *) rawBuf(self);
}

/*
    Call setLen/bufLen to know how much memory you own before any kind of writing
*/

inline unsigned char *rawBufMut(shift_buffer_t *self)
{
    return (void *) &(self->pbuf[self->curpos]);
}

inline void writeRaw(shift_buffer_t *restrict self, const void *restrict buffer, unsigned int len)
{
    memcpy(rawBufMut(self), buffer, len);
}

inline void writeI32(shift_buffer_t *self, int32_t data)
{
    *(int32_t *) rawBufMut(self) = data;
}

inline void writeUI32(shift_buffer_t *self, uint32_t data)
{
    *(uint32_t *) rawBufMut(self) = data;
}

inline void writeI16(shift_buffer_t *self, int16_t data)
{
    *(int16_t *) rawBufMut(self) = data;
}

inline void writeUI16(shift_buffer_t *self, uint16_t data)
{
    *(uint16_t *) rawBufMut(self) = data;
}

inline void writeUI8(shift_buffer_t *self, uint8_t data)
{
    *(uint8_t *) rawBufMut(self) = data;
}
