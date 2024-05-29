#include "shiftbuffer.h"
#include <assert.h> // for assert
#include <math.h>   //cel,log2,pow
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern bool           isShallow(shift_buffer_t *self);
extern unsigned int   lCap(shift_buffer_t *self);
extern unsigned int   rCap(shift_buffer_t *self);
extern unsigned int   bufLen(shift_buffer_t *self);
extern void           setLen(shift_buffer_t *self, unsigned int bytes);
extern void           reserveBufSpace(shift_buffer_t *self, unsigned int bytes);
extern void           consume(shift_buffer_t *self, unsigned int bytes);
extern void           shiftl(shift_buffer_t *self, unsigned int bytes);
extern void           shiftr(shift_buffer_t *self, unsigned int bytes);
extern const void    *rawBuf(shift_buffer_t *self);
extern unsigned char *rawBufMut(shift_buffer_t *self);
extern void           writeRaw(shift_buffer_t *restrict self, const void *restrict buffer, unsigned int len);
extern void           writeI32(shift_buffer_t *self, int32_t data);
extern void           writeUI32(shift_buffer_t *self, uint32_t data);
extern void           writeI16(shift_buffer_t *self, int16_t data);
extern void           writeUI16(shift_buffer_t *self, uint16_t data);
extern void           writeUI8(shift_buffer_t *self, uint8_t data);
extern void           readUI8(shift_buffer_t *self, uint8_t *dest);
extern void           readUI16(shift_buffer_t *self, uint16_t *dest);
extern void           readUI64(shift_buffer_t *self, uint64_t *dest);

void destroyShiftBuffer(shift_buffer_t *self)
{
    // if its a shallow then the underlying buffer survives
    *(self->refc) -= 1;

    if (*(self->refc) <= 0)
    {
        if (self->shallow_offset != 0)
        {
            self->pbuf -= self->shallow_offset;
        }
        free(self->pbuf);
        free(self->refc);
    }
    free(self);
}

shift_buffer_t *newShiftBuffer(unsigned int pre_cap)
{
    if (pre_cap != 0 && pre_cap % 16 != 0)
    {
        pre_cap = (unsigned int) pow(2, ceil(16 + log2(pre_cap)));
    }

    unsigned int real_cap = pre_cap * 2;

    shift_buffer_t *self = malloc(sizeof(shift_buffer_t));
    self->pbuf           = malloc(real_cap);

    if (real_cap > 0) // map the virtual memory page to physical memory
    {
        unsigned int i = 0;
        do
        {
            self->pbuf[i] = 0x0;
            i += 4096;
        } while (i < real_cap);
    }

    self->calc_len = 0;
    self->curpos   = pre_cap;
    self->full_cap = real_cap;
    self->refc     = malloc(sizeof(unsigned int));
    *(self->refc)  = 1;
    return self;
}

shift_buffer_t *newShallowShiftBuffer(shift_buffer_t *owner)
{
    *(owner->refc) += 1;
    shift_buffer_t *shallow = malloc(sizeof(shift_buffer_t));
    *shallow                = *owner;
    // freeze the shallow buffer
    shallow->shallow_offset = owner->curpos;
    shallow->pbuf += owner->curpos;
    shallow->curpos   = 0;
    shallow->full_cap = owner->calc_len;
    return shallow;
}

void reset(shift_buffer_t *self, unsigned int pre_cap)
{
    assert(! isShallow(self));
    if (pre_cap != 0 && pre_cap % 16 != 0)
    {
        pre_cap = (unsigned int) pow(2, ceil(16 + log2(pre_cap)));
    }
    unsigned int real_cap = pre_cap * 2;

    if (self->full_cap != real_cap)
    {
        free(self->pbuf);
        self->pbuf     = malloc(real_cap);
        self->full_cap = real_cap;
    }
    self->calc_len = 0;
    self->curpos   = pre_cap;
}

void unShallow(shift_buffer_t *self)
{
    if (*(self->refc) <= 1)
    {
        // not a shallow
        assert(false);
        return;
    }

    *(self->refc) -= 1;
    self->refc    = malloc(sizeof(unsigned int));
    *(self->refc) = 1;
    char *old_buf = self->pbuf;
    self->pbuf    = malloc(self->full_cap);
    memcpy(&(self->pbuf[self->curpos]), &(old_buf[self->curpos]), (self->calc_len));
}

void expand(shift_buffer_t *self, unsigned int increase)
{
    if (isShallow(self))
    {
        const unsigned int old_realcap = self->full_cap;
        unsigned int       new_realcap = (unsigned int) pow(2, ceil(log2((old_realcap * 2) + (increase * 2))));
        // unShallow
        *(self->refc) -= 1;
        self->refc       = malloc(sizeof(unsigned int));
        *(self->refc)    = 1;
        char *old_buf    = self->pbuf;
        self->pbuf       = malloc(new_realcap);
        unsigned int dif = new_realcap - self->full_cap;
        memcpy(&(self->pbuf[self->curpos + dif]), &(old_buf[self->curpos]), self->calc_len);
        self->curpos += dif;
        self->full_cap = new_realcap;
    }
    else
    {
        const unsigned int old_realcap = self->full_cap;
        unsigned int       new_realcap = (unsigned int) pow(2, ceil(log2((old_realcap * 2) + (increase * 2))));
        char              *old_buf     = self->pbuf;
        self->pbuf                     = malloc(new_realcap);
        unsigned int dif               = new_realcap - self->full_cap;
        memcpy(&(self->pbuf[self->curpos + dif]), &(old_buf[self->curpos]), self->calc_len);
        self->curpos += dif;
        self->full_cap = new_realcap;
        free(old_buf);
    }
}

void concatBuffer(shift_buffer_t *restrict root, shift_buffer_t *restrict buf)
{
    unsigned int root_length   = bufLen(root);
    unsigned int append_length = bufLen(buf);
    setLen(root, root_length + append_length);
    memcpy(rawBufMut(root) + root_length, rawBuf(buf), append_length);
}

void sliceBufferTo(shift_buffer_t *dest, shift_buffer_t *source, unsigned int bytes)
{
    assert(bytes <= bufLen(source));
    assert(bufLen(dest) == 0);
    const unsigned int total     = bufLen(source);
    const unsigned int threshold = 100;

    if (bytes <= (total / 2) + threshold)
    {
        setLen(dest, bytes);
        memcpy(rawBufMut(dest), rawBuf(source), bytes);
        shiftr(source, bytes);
        return;
    }

    shift_buffer_t tmp = *source;
    *source            = *dest;
    *dest              = tmp;

    setLen(source, total - bytes);
    memcpy(rawBufMut(source), &(((char *) rawBuf(dest))[bytes]), total - bytes);
    setLen(dest, bytes);
}

shift_buffer_t *sliceBuffer(shift_buffer_t *self, unsigned int bytes)
{
    assert(bytes <= bufLen(self));

    if (bytes <= bufLen(self) / 2)
    {
        shift_buffer_t *newbuf = newShiftBuffer(self->full_cap / 2);
        setLen(newbuf, bytes);
        memcpy(rawBufMut(newbuf), rawBuf(self), bytes);
        shiftr(self, bytes);
        return newbuf;
    }

    shift_buffer_t *newbuf   = newShiftBuffer(self->full_cap / 2);
    void           *tmp_refc = self->refc;
    void           *tmp_pbuf = self->pbuf;
    self->refc               = newbuf->refc;
    self->pbuf               = newbuf->pbuf;
    *newbuf                  = (struct shift_buffer_s){.calc_len = self->calc_len,
                                                       .curpos   = self->curpos,
                                                       .full_cap = self->full_cap,
                                                       .refc     = tmp_refc,
                                                       .pbuf     = tmp_pbuf};

    memcpy(rawBufMut(self), &(((char *) rawBuf(newbuf))[bytes]), bufLen(newbuf) - bytes);
    shiftr(self, bytes);
    setLen(newbuf, bytes);
    return newbuf;
}
shift_buffer_t *shallowSliceBuffer(shift_buffer_t *self, unsigned int bytes)
{
    assert(bytes <= bufLen(self));
    shift_buffer_t *shallow = newShallowShiftBuffer(self);
    setLen(shallow, bytes);
    shiftr(self, bytes);
    return shallow;
}
