#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


struct shift_buffer_s
{
    size_t lenpos;
    size_t curpos;
    size_t cap; // half of full cap
    char *pbuf;
    unsigned int* refc;
};
typedef struct shift_buffer_s shift_buffer_t;

void destroyShiftBuffer(shift_buffer_t *self);

shift_buffer_t *newShiftBuffer(size_t pre_cap);
shift_buffer_t *newShadowShiftBuffer(shift_buffer_t *owner);

void reset(shift_buffer_t *self);



void expand(shift_buffer_t *self, size_t increase);


//  how many bytes we can fill without realloc
inline size_t lCap(shift_buffer_t *self) { return self->curpos; }
inline size_t rCap(shift_buffer_t *self) { return (self->cap * 2 - self->curpos); }
inline void shiftl(shift_buffer_t *self, size_t bytes)
{
    if (lCap(self) < bytes)
        expand(self, (bytes - lCap(self)));
    self->curpos -= bytes;
}

inline void shiftr(shift_buffer_t *self, size_t bytes)
{
    if (rCap(self) < bytes)
        expand(self, (bytes - rCap(self)));
    self->curpos += bytes;
}


inline size_t bufLen(shift_buffer_t *self) { return self->lenpos - self->curpos; }

inline void setLen(shift_buffer_t *self, size_t bytes)
{
    if (rCap(self) < bytes)
        expand(self, (bytes - rCap(self)));
    self->lenpos = self->curpos + bytes;
}

inline void reserve(shift_buffer_t *self, size_t bytes)
{
    if (rCap(self) < bytes)
        expand(self, (bytes - rCap(self)));
}

inline void consume(shift_buffer_t *self, size_t bytes)
{
    setLen(self, bufLen(self) - bytes);
}

inline unsigned  char *rawBuf(shift_buffer_t *self) {return (unsigned  char *)&(self->pbuf[self->curpos]); }



void writeRaw(shift_buffer_t *self, unsigned char* buffer, size_t len);

void writeI32(shift_buffer_t *self, int32_t data);
void writeUI32(shift_buffer_t *self, uint32_t data);
void writeI16(shift_buffer_t *self, int16_t data);
void writeUI16(shift_buffer_t *self, uint16_t data);
void writeUI8(shift_buffer_t *self, uint8_t data);
void readUI8(shift_buffer_t *self, uint8_t *dest);
void readUI16(shift_buffer_t *self, uint16_t* dest);

