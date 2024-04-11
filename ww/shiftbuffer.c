#include "shiftbuffer.h"
#include "hv/hlog.h"
#include <assert.h> // for assert
#include <math.h>   //cel,log2,pow

extern unsigned int lCap(shift_buffer_t *self);
extern unsigned int rCap(shift_buffer_t *self);
extern unsigned int bufLen(shift_buffer_t *self);
extern void setLen(shift_buffer_t *self, unsigned int bytes);
extern void reserve(shift_buffer_t *self, unsigned int bytes);
extern void consume(shift_buffer_t *self, unsigned int bytse);
extern void shiftl(shift_buffer_t *self, unsigned int bytes);
extern void shiftr(shift_buffer_t *self, unsigned int bytes);
extern const void *rawBuf(shift_buffer_t *self);
extern unsigned char *rawBufMut(shift_buffer_t *self);
extern void writeRaw(shift_buffer_t *restrict self, const void *restrict buffer, unsigned int len);
extern void writeI32(shift_buffer_t *self, int32_t data);
extern void writeUI32(shift_buffer_t *self, uint32_t data);
extern void writeI16(shift_buffer_t *self, int16_t data);
extern void writeUI16(shift_buffer_t *self, uint16_t data);
extern void writeUI8(shift_buffer_t *self, uint8_t data);
extern void readUI8(shift_buffer_t *self, uint8_t *dest);
extern void readUI16(shift_buffer_t *self, uint16_t *dest);

void destroyShiftBuffer(shift_buffer_t *self)
{
    // if its a shadow then the underlying buffer survives
    *(self->refc) -= 1;

    if (*(self->refc) <= 0)
    {
        free(self->pbuf);
        free(self->refc);
    }
    free(self);
}

shift_buffer_t *newShiftBuffer(unsigned int pre_cap)
{
    assert(pre_cap >= 0);
    unsigned int real_cap = pre_cap * 2;

    shift_buffer_t *self = malloc(sizeof(shift_buffer_t));
    self->pbuf = malloc(real_cap);

    if (real_cap > 0) // map the virtual memory page to physical memory
    {
        unsigned int i = 0;
        do
        {
            self->pbuf[i] = 0x0;
            i += 4096;
        } while (i < real_cap);
    }

    self->lenpos = pre_cap;
    self->curpos = pre_cap;
    self->cap = pre_cap;
    self->full_cap = real_cap;
    self->refc = malloc(sizeof(unsigned int));
    *(self->refc) = 1;
    return self;
}

shift_buffer_t *newShadowShiftBuffer(shift_buffer_t *owner)
{
    // shadow buffers point to same memory but they can be detached if 1 of
    // them requires buffer resize, this is the fatest way to copy a buffer and
    // keep it for later use
    *(owner->refc) += 1;
    shift_buffer_t *shadow = malloc(sizeof(shift_buffer_t));
    *shadow = *owner;
    return shadow;
}

void reset(shift_buffer_t *self, unsigned int cap)
{

    if (self->cap != cap)
    {
        unsigned int real_cap = cap * 2;
        free(self->pbuf);
        self->pbuf = malloc(real_cap);
        self->cap = cap;
        self->full_cap = real_cap;
    }
    self->lenpos = self->cap;
    self->curpos = self->cap;
}

// all caps in this function are REAL
void expand(shift_buffer_t *self, unsigned int increase)
{
    const bool keep = self->curpos != self->lenpos;
    if (*(self->refc) > 1)
    {
        // LOGF("Expanding a shiftbuffer while it has refs is false assumption!");
        // assert(false);
        const unsigned int realcap = self->full_cap;
        unsigned int new_realcap = pow(2, ceil(log2((float)(realcap * 2) + (increase * 2))));

        // detach!
        *(self->refc) -= 1;
        self->refc = malloc(sizeof(unsigned int));
        *(self->refc) = 1;

        char *old_buf = self->pbuf;

        self->pbuf = malloc(new_realcap);
        unsigned int dif = (new_realcap / 2) - self->cap;
        if (keep)
            memcpy(&(self->pbuf[dif]), &(old_buf[0]), realcap);
        self->curpos += dif;
        self->lenpos += dif;
        self->cap = new_realcap / 2;
        self->full_cap = new_realcap;
    }
    else
    {
        const unsigned int realcap = self->cap * 2;
        unsigned int new_realcap = pow(2, ceil(log2((float)(realcap * 2) + (increase * 2))));
        // #ifdef DEBUG
        //     LOGW("Allocated more memory! oldcap = %zu , increase = %zu , newcap = %zu", self->cap * 2, increase, new_realcap);
        // #endif
        self->pbuf = keep ? realloc(self->pbuf, new_realcap) : malloc(new_realcap);
        unsigned int dif = (new_realcap / 2) - self->cap;
        self->curpos += dif;
        self->lenpos += dif;
        self->cap = new_realcap / 2;
        self->full_cap = new_realcap;
    }
}
