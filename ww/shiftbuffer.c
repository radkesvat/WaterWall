#include "shiftbuffer.h"
#include "hv/hlog.h"
#include <assert.h> // for assert
#include <math.h>   //cel,log2,pow
#include <string.h> // memmove,memcpy
#define NOMINMAX
#include <stdlib.h> // free

extern size_t lCap(shift_buffer_t *self);
extern size_t rCap(shift_buffer_t *self);
extern size_t bufLen(shift_buffer_t *self);
extern void setLen(shift_buffer_t *self, size_t bytes);
extern void reserve(shift_buffer_t *self, size_t bytes);
extern void consume(shift_buffer_t *self, size_t bytse);
extern void shiftl(shift_buffer_t *self, size_t bytes);
extern void shiftr(shift_buffer_t *self, size_t bytes);
extern unsigned char *rawBuf(shift_buffer_t *self);

void destroyShiftBuffer(shift_buffer_t *self)
{
    *(self->refc) -= 1;

    if (*(self->refc) <= 0)
    {
        free(self->pbuf);
        free(self->refc);
    }
    free(self);
}

shift_buffer_t *newShiftBuffer(size_t pre_cap)
{
    assert(pre_cap >= 0);
    size_t real_cap = pre_cap * 2;

    shift_buffer_t *self = malloc(sizeof(shift_buffer_t));
    self->pbuf = malloc(real_cap);
    self->lenpos = pre_cap;
    self->curpos = pre_cap;
    self->cap = pre_cap;
    self->refc = malloc(sizeof(unsigned int));
    *(self->refc) = 1;
    return self;
}

shift_buffer_t *newShadowShiftBuffer(shift_buffer_t *owner)
{
    *(owner->refc) += 1;
    shift_buffer_t *shadow = malloc(sizeof(shift_buffer_t));
    *shadow = *owner;
    return shadow;
}

void reset(shift_buffer_t *self)
{
    self->lenpos = self->cap;
    self->curpos = self->cap;
}

// all caps in this function are REAL
void expand(shift_buffer_t *self, size_t increase)
{
    if (*(self->refc) > 1)
    {
        // LOGF("Expanding a shiftbuffer while it has refs is false assumption!");
        // assert(false);

        // detach!
        *(self->refc) -= 1;
        self->refc = malloc(sizeof(unsigned int));
        *(self->refc) = 1;

        char *old_buf = self->pbuf;
        const size_t realcap = self->cap * 2;
        size_t new_realcap = pow(2, ceil(log2((float)(realcap * 2) + (increase * 2))));
        self->pbuf = malloc(new_realcap);
        size_t dif = (new_realcap / 2) - self->cap;
        memcpy(&(self->pbuf[dif]), &(old_buf[0]), realcap);
        self->curpos += dif;
        self->lenpos += dif;
        self->cap = new_realcap / 2;
    }
    else
    {
        const size_t realcap = self->cap * 2;
        size_t new_realcap = pow(2, ceil(log2((float)(realcap * 2) + (increase * 2))));
        // #ifdef DEBUG
        //     LOGW("Allocated more memory! oldcap = %zu , increase = %zu , newcap = %zu", self->cap * 2, increase, new_realcap);
        // #endif
        self->pbuf = realloc(self->pbuf, new_realcap);
        size_t dif = (new_realcap / 2) - self->cap;
        memmove(&self->pbuf[dif], &self->pbuf[0], realcap);
        self->curpos += dif;
        self->lenpos += dif;
        self->cap = new_realcap / 2;
    }
}


void writeRaw(shift_buffer_t *self, unsigned char *buffer, size_t len)
{
    memcpy(rawBuf(self), buffer, len);
}

void writeI32(shift_buffer_t *self, int32_t data)
{
    writeRaw(self, (char *)&data, sizeof(int32_t));
}

void writeUI32(shift_buffer_t *self, uint32_t data)
{
    writeRaw(self, (unsigned char *)&data, sizeof(uint32_t));
}

void writeI16(shift_buffer_t *self, int16_t data)
{
    writeRaw(self, (unsigned char *)&data, sizeof(int16_t));
}

void writeUI16(shift_buffer_t *self, uint16_t data)
{
    writeRaw(self, (unsigned char *)&data, sizeof(uint16_t));
}

void writeUI8(shift_buffer_t *self, uint8_t data)
{
    writeRaw(self, (unsigned char *)&data, sizeof(uint8_t));
}

void readUI8(shift_buffer_t *self, uint8_t *dest)
{
    memcpy(dest, rawBuf(self), sizeof(uint8_t));
}
void readUI16(shift_buffer_t *self, uint16_t *dest)
{
    memcpy(dest, rawBuf(self), sizeof(uint16_t));
}
