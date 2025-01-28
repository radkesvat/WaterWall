#include "shiftbuffer.h"
#include "wlibc.h"

// #define LEFTPADDING  ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 10) : (1U << 8)) - (sizeof(uint32_t) * 3))
// #define RIGHTPADDING ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 9) : (1U << 7)))

// #define TOTALPADDING ((uint32_t) (sizeof(sbuf_t) + (LEFTPADDING + RIGHTPADDING)))

void sbufDestroy(sbuf_t *b)
{
    memoryFree(b);
}

sbuf_t *sbufNewWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    if (minimum_capacity != 0 && minimum_capacity % kCpuLineCacheSize != 0)
    {
        minimum_capacity = (max(kCpuLineCacheSize, minimum_capacity) + kCpuLineCacheSizeMin1) & ~kCpuLineCacheSizeMin1;
    }

    uint32_t real_cap = minimum_capacity + pad_left;
    sbuf_t  *b        = memoryAllocate(real_cap);

    b->len      = 0;
    b->curpos   = pad_left;
    b->capacity = real_cap;
    b->l_pad    = pad_left;

    return b;
}

sbuf_t *sbufNew(uint32_t minimum_capacity)
{
    return sbufNewWithPadding(minimum_capacity, 0);
}

sbuf_t *sbufDuplicate(sbuf_t *b)
{
    sbuf_t *newbuf = sbufNewWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);
    sbufSetLength(newbuf, sbufGetBufLength(b));
    memoryCopy128(sbufGetMutablePtr(newbuf), sbufGetRawPtr(b), sbufGetBufLength(b));

    return newbuf;
}

sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict const buf)
{
    uint32_t root_length   = sbufGetBufLength(root);
    uint32_t append_length = sbufGetBufLength(buf);
    root                   = sbufReserveSpace(root, root_length + append_length);
    sbufSetLength(root, root_length + append_length);

    memoryCopy128(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);

    return root;
}



sbuf_t *sbufMoveTo(sbuf_t *restrict dest, sbuf_t *restrict source, const uint32_t bytes)
{
    assert(bytes <= sbufGetBufLength(source));
    assert(sbufGetBufLength(dest) == 0);

    dest = sbufReserveSpace(dest, bytes);
    sbufSetLength(dest, bytes);

    sbufWriteBuf(dest, source, bytes);

    sbufShiftRight(source, bytes);

    return dest;
}

sbuf_t *sbufSlice(sbuf_t *const b, const uint32_t bytes)
{
    sbuf_t *newbuf = sbufNewWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad, b->r_pad);
    sbufMoveTo(newbuf, b, bytes);
    return newbuf;
}
