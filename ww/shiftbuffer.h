#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h> // memmove,memcpy
#include <stdlib.h> // free

#if defined(DEBUG) && !defined(hlog)
#include "loggers/network_logger.h" //some logs needs to be printed on debug mode
#endif

struct shift_buffer_s
{
    unsigned int lenpos;
    unsigned int curpos;
    unsigned int cap; // half of full cap
    unsigned int full_cap; 
    unsigned int *refc;
    char *pbuf;
};
typedef struct shift_buffer_s shift_buffer_t;

void destroyShiftBuffer(shift_buffer_t *self);

shift_buffer_t *newShiftBuffer(unsigned int pre_cap);
shift_buffer_t *newShadowShiftBuffer(shift_buffer_t *owner);

void reset(shift_buffer_t *self,unsigned int cap);

void detachWithSize(shift_buffer_t *self, unsigned int newsize);
void expand(shift_buffer_t *self, unsigned int increase);

//  how many bytes we can fill without realloc
inline unsigned int lCap(shift_buffer_t *self) { return self->curpos; }
inline unsigned int rCap(shift_buffer_t *self) { return (self->full_cap - self->curpos); }
inline void shiftl(shift_buffer_t *self, unsigned int bytes)
{
    if (lCap(self) < bytes)
        expand(self, (bytes - lCap(self)));
    self->curpos -= bytes;
}

inline void shiftr(shift_buffer_t *self, unsigned int bytes)
{
    if (rCap(self) < bytes)
        expand(self, (bytes - rCap(self)));
    self->curpos += bytes;
}

inline unsigned int bufLen(shift_buffer_t *self) { return self->lenpos - self->curpos; }

inline void setLen(shift_buffer_t *self, unsigned int bytes)
{
    if (rCap(self) < bytes)
        expand(self, (bytes - rCap(self)));
    self->lenpos = self->curpos + bytes;
}

inline void reserve(shift_buffer_t *self, unsigned int bytes)
{
    if (rCap(self) < bytes)
        expand(self, (bytes - rCap(self)));
}

inline void consume(shift_buffer_t *self, unsigned int bytes)
{
    setLen(self, bufLen(self) - bytes);
}

inline const void *rawBuf(shift_buffer_t *self) { return (void *)&(self->pbuf[self->curpos]); }
inline unsigned char *rawBufMut(shift_buffer_t *self)
{
#ifdef DEBUG
    if (*(self->refc) > 1)
        LOGW("writing to a buffer with (refs > 1) is dangerous, do a full copy in this case");
#endif
    return (void*)&(self->pbuf[self->curpos]);
}

inline void writeRaw(shift_buffer_t *restrict self, const void *restrict buffer, unsigned int len)
{
    memcpy(rawBufMut(self), buffer, len);
}

inline void writeI32(shift_buffer_t *self, int32_t data)
{
    writeRaw(self, &data, sizeof(int32_t));
}

inline void writeUI32(shift_buffer_t *self, uint32_t data)
{
    writeRaw(self, &data, sizeof(uint32_t));
}

inline void writeI16(shift_buffer_t *self, int16_t data)
{
    writeRaw(self, &data, sizeof(int16_t));
}

inline void writeUI16(shift_buffer_t *self, uint16_t data)
{
    writeRaw(self, &data, sizeof(uint16_t));
}

inline void writeUI8(shift_buffer_t *self, uint8_t data)
{
    writeRaw(self, &data, sizeof(uint8_t));
}

inline void readUI8(shift_buffer_t *self, uint8_t *dest)
{
    memcpy(dest, rawBuf(self), sizeof(uint8_t));
}
inline void readUI16(shift_buffer_t *self, uint16_t *dest)
{
    memcpy(dest, rawBuf(self), sizeof(uint16_t));
}
