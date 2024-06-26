#include "shiftbuffer.h"
#include "generic_pool.h"
#include "utils/mathutils.h"
#include "ww.h"
#include <assert.h> // for assert
#include <math.h>   //cel,log2,pow
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PREPADDING (ram_profile >= kRamProfileS2Memory ? (1U << 13) : ((1U << 8) + 512))

pool_item_t *allocShiftBufferPoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    shift_buffer_t *self = malloc(sizeof(shift_buffer_t));

    *self = (shift_buffer_t){
        .refc = malloc(sizeof(self->refc[0])),
    };
    return self;
}
void destroyShiftBufferPoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    shift_buffer_t *self = item;

    free(self->refc);
    free(self);
}

void destroyShiftBuffer(uint8_t tid, shift_buffer_t *self)
{
    assert(*(self->refc) > 0);
    // if its a shallow then the underlying buffer survives
    *(self->refc) -= 1;

    if (*(self->refc) <= 0)
    {
        free(self->pbuf - self->_offset);
        reusePoolItem(shift_buffer_pools[tid], self);
    }
    else
    {
        self->refc = malloc(sizeof(self->refc[0]));
        reusePoolItem(shift_buffer_pools[tid], self);
    }
}

shift_buffer_t *newShiftBuffer(uint8_t tid, unsigned int pre_cap) // NOLINT
{
    if (pre_cap != 0 && pre_cap % 16 != 0)
    {
        pre_cap = (unsigned int) pow(2, ceil(log2((double) max(16, pre_cap))));
    }

    unsigned int real_cap = pre_cap + (PREPADDING);

    // shift_buffer_t *self = malloc(sizeof(shift_buffer_t));
    shift_buffer_t *self = (shift_buffer_t *) popPoolItem(shift_buffer_pools[tid]);

    self->calc_len = 0;
    self->_offset  = 0;
    self->curpos   = PREPADDING;
    self->full_cap = real_cap;
    self->pbuf     = malloc(real_cap);
    // self->refc     = malloc(sizeof(self->refc[0])),
    *(self->refc) = 1;

    if (real_cap > 0) // map the virtual memory page to physical memory
    {
        unsigned int i = 0;
        do
        {
            self->pbuf[i] = 0x0;
            i += 4096;
        } while (i < real_cap);
    }

    return self;
}

shift_buffer_t *newShallowShiftBuffer(uint8_t tid, shift_buffer_t *owner)
{
    *(owner->refc) += 1;
    shift_buffer_t *shallow = (shift_buffer_t *) popPoolItem(shift_buffer_pools[tid]);
    free(shallow->refc);
    *shallow = *owner;

    return shallow;
}

// this function is made for internal use (most probably in bufferpool)
void reset(shift_buffer_t *self, unsigned int pre_cap)
{
    assert(! isShallow(self));

    if (pre_cap != 0 && pre_cap % 16 != 0)
    {
        pre_cap = (unsigned int) pow(2, ceil(log2(((double) max(16, pre_cap)))));
    }

    unsigned int real_cap = pre_cap + (PREPADDING);

    if (self->full_cap != real_cap)
    {
        free(self->pbuf - self->_offset);
        self->pbuf     = malloc(real_cap);
        self->full_cap = real_cap;
        // memset(self->pbuf, 0, real_cap);
    }
    self->calc_len = 0;
    self->_offset  = 0;
    self->curpos   = PREPADDING;
}

void unShallow(shift_buffer_t *self)
{
    // not a shallow
    assert(*(self->refc) > 1);

    *(self->refc) -= 1;
    self->refc    = malloc(sizeof(unsigned int));
    *(self->refc) = 1;
    char *old_buf = self->pbuf;
    self->pbuf    = malloc(self->full_cap);
    self->_offset = 0;
    memcpy(&(self->pbuf[self->curpos]), &(old_buf[self->curpos]), (self->calc_len));
}

void expand(shift_buffer_t *self, unsigned int increase)
{
    if (isShallow(self))
    {
        const unsigned int old_realcap = self->full_cap;
        unsigned int       new_realcap = (unsigned int) pow(2, ceil(log2((old_realcap) + (increase * 2))));
        // unShallow
        *(self->refc) -= 1;
        self->refc       = malloc(sizeof(unsigned int));
        *(self->refc)    = 1;
        char *old_buf    = self->pbuf;
        self->pbuf       = malloc(new_realcap);
        self->_offset    = 0;
        unsigned int dif = (new_realcap - self->full_cap) / 2;
        memcpy(&(self->pbuf[self->curpos + dif]), &(old_buf[self->curpos]), self->calc_len);
        self->curpos += dif;
        self->full_cap = new_realcap;
    }
    else
    {
        const unsigned int old_realcap = self->full_cap;
        unsigned int       new_realcap = (unsigned int) pow(2, ceil(log2((old_realcap) + (increase * 2))));
        char              *old_buf     = self->pbuf;
        self->pbuf                     = malloc(new_realcap);
        unsigned int dif               = (new_realcap - self->full_cap) / 2;
        memcpy(&(self->pbuf[self->curpos + dif]), &(old_buf[self->curpos]), self->calc_len);
        self->curpos += dif;
        self->full_cap = new_realcap;
        free(old_buf - self->_offset);
        self->_offset = 0;
    }
}

void concatBuffer(shift_buffer_t *restrict root, const shift_buffer_t *restrict const buf)
{
    unsigned int root_length   = bufLen(root);
    unsigned int append_length = bufLen(buf);
    setLen(root, root_length + append_length);
    memcpy(rawBufMut(root) + root_length, rawBuf(buf), append_length);
}

void sliceBufferTo(shift_buffer_t *restrict dest, shift_buffer_t *restrict source, const unsigned int bytes)
{
    assert(bytes <= bufLen(source));
    assert(bufLen(dest) == 0);
    const unsigned int        total      = bufLen(source);
    static const unsigned int kThreshold = 128;

    if (bytes <= (total / 2) + kThreshold)
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

shift_buffer_t *sliceBuffer(const uint8_t tid, shift_buffer_t *const self, const unsigned int bytes)
{
    assert(bytes <= bufLen(self));

    shift_buffer_t *newbuf = newShiftBuffer(tid, self->full_cap / 2);

    if (bytes <= bufLen(self) / 2)
    {
        setLen(newbuf, bytes);
        memcpy(rawBufMut(newbuf), rawBuf(self), bytes);
        shiftr(self, bytes);
        return newbuf;
    }

    void        *tmp_pbuf   = self->pbuf;
    void        *tmp_refc   = self->refc;
    unsigned int tmp_offset = self->_offset;

    self->refc    = newbuf->refc;
    self->pbuf    = newbuf->pbuf;
    self->_offset = newbuf->_offset;
    *newbuf       = (struct shift_buffer_s){.calc_len = self->calc_len,
                                            .curpos   = self->curpos,
                                            .full_cap = self->full_cap,
                                            .pbuf     = tmp_pbuf,
                                            .refc     = tmp_refc,
                                            ._offset  = tmp_offset};

    memcpy(rawBufMut(self), &(((char *) rawBuf(newbuf))[bytes]), bufLen(newbuf) - bytes);
    shiftr(self, bytes);
    setLen(newbuf, bytes);
    return newbuf;
}

shift_buffer_t *shallowSliceBuffer(const uint8_t tid, shift_buffer_t *self, const unsigned int bytes)
{
    assert(bytes <= bufLen(self));

    if (! isShallow(self) && self->_offset != 0)
    {
        self->curpos += self->_offset;
        self->pbuf -= self->_offset;
        self->full_cap += self->_offset;
        self->_offset = 0;
    }

    shift_buffer_t *shallow = newShallowShiftBuffer(tid, self);
    setLen(shallow, bytes);
    constrainRight(shallow);

    shiftr(self, bytes);
    constrainLeft(self);

    return shallow;
}
