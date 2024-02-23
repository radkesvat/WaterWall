#include "shiftbuffer.h"
#include "hv/hlog.h"
#include <assert.h> // for assert
#include <math.h>   //cel,log2,pow
#include <string.h> // memmove,memcpy
#include <stdlib.h> // free

extern size_t lCap(shift_buffer_t *self);
extern size_t rCap(shift_buffer_t *self);
extern size_t bufLen(shift_buffer_t *self);
extern void setLen(shift_buffer_t *self, size_t bytes);
extern void reserve(shift_buffer_t *self, size_t bytes);
extern void consume(shift_buffer_t *self, size_t bytse);
extern char *rawBuf(shift_buffer_t *self);

void destroyShiftBuffer(shift_buffer_t *self)
{

    if (self->shadowed)
    {
        (self->ref)->refc -= 1;

        if ((self->ref)->refc < 0)
        {
            free((self->ref)->pbuf);
            free((self->ref));
        }
        free(self);
    }
    else
    {
        if (self->refc <= 0)
        {
            free(self->pbuf);
            free(self);
        }
        else
            self->refc -= 1;
    }
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
    self->shadowed = false;
    self->refc = 0;
    self->ref = NULL;
    return self;
}

shift_buffer_t *newShadowShiftBuffer(shift_buffer_t *owner)
{
    shift_buffer_t *root = owner;
    if (root->shadowed == true)
    {
        root = root->ref;
    }

    root->refc += 1;
    shift_buffer_t *shadow = newShiftBuffer(0);
    *shadow = *owner;
    shadow->shadowed = true;
    shadow->ref = root;
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
    if(self->refc > 0){
        LOGF("Expanding a shiftbuffer while it has refs is false assumption!");
        assert(false);
    }

    size_t newcap = pow(2, ceil(log2((float)(self->cap * 2) + (increase * 2))));

// #ifdef DEBUG
//     LOGW("Allocated more memory! oldcap = %zu , increase = %zu , newcap = %zu", self->cap * 2, increase, newcap);
// #endif
    self->pbuf = realloc(self->pbuf, newcap);

    size_t dif = (newcap / 2) - self->cap;

    memmove(&self->pbuf[dif], &self->pbuf[0], self->cap * 2);

    self->curpos += dif;
    self->lenpos += dif;

    self->cap = newcap / 2;
}

void shiftl(shift_buffer_t *self, size_t bytes)
{
    if (lCap(self) < bytes)
        expand(self, (bytes - lCap(self)));

    self->curpos -= bytes;
}

void shiftr(shift_buffer_t *self, size_t bytes)
{
#ifdef DEBUG_BUILD
    assert(self->curpos + bytes <= self->lenpos);
#endif

    if (rCap(self) < bytes)
        expand(self, (bytes - rCap(self)));
    self->curpos += bytes;
}

void writeRaw(shift_buffer_t *self, char *buffer, size_t len)
{
    memcpy(rawBuf(self), buffer, len);
}

void writeI32(shift_buffer_t *self, int32_t data)
{
    writeRaw(self, (char *)&data, sizeof(data));
}

void writeUI32(shift_buffer_t *self, uint32_t data)
{
    writeRaw(self, (char *)&data, sizeof(data));
}

void writeI16(shift_buffer_t *self, int16_t data)
{
    writeRaw(self, (char *)&data, sizeof(data));
}

void writeUI16(shift_buffer_t *self, uint16_t data)
{
    writeRaw(self, (char *)&data, sizeof(data));
}

void readUI8(shift_buffer_t *self, uint8_t *dest)
{
    memcpy(dest, rawBuf(self), sizeof(dest));
}
void readUI16(shift_buffer_t *self, uint16_t *dest)
{
    memcpy(dest, rawBuf(self), sizeof(dest));
}
