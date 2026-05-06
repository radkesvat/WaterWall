/*
 * Implements sbuf creation, duplication, slicing, and concatenation routines.
 */

#include "shiftbuffer.h"
#include "wlibc.h"

uint16_t sbufAlignLeftPadding(uint16_t pad_left)
{
    const uint32_t aligned_pad = (((uint32_t) pad_left) + 31U) & ~31U;

    if (aligned_pad > UINT16_MAX)
    {
        printError("sbuf: left padding overflow after alignment");
        terminateProgram(1);
    }

    return (uint16_t) aligned_pad;
}

void sbufDestroy(sbuf_t *b)
{
    if (UNLIKELY(b->is_temporary))
    {
        return;
    }

    memoryFree(b->original_ptr);
}

sbuf_t *sbufCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    pad_left = sbufAlignLeftPadding(pad_left);

    if (minimum_capacity != 0 && minimum_capacity % kCpuLineCacheSize != 0)
    {
        minimum_capacity =
            (max(kCpuLineCacheSize, minimum_capacity) + kCpuLineCacheSizeMin1) & (~kCpuLineCacheSizeMin1);
    }

    if (minimum_capacity > UINT32_MAX - pad_left)
    {
        printError("sbuf: capacity overflow (minimum_capacity + pad_left)");
        exit(1);
    }

    uint32_t real_cap = minimum_capacity + pad_left;

    size_t total_size = real_cap + sizeof(sbuf_t) + 31;
    void  *raw_ptr    = memoryAllocate(total_size);

    sbuf_t *b = (sbuf_t *) ALIGN2(raw_ptr, 32);

    b->original_ptr = raw_ptr;

#ifdef DEBUG
    memorySet(b->buf, 0x55, real_cap);
#endif

    b->is_temporary = false;
    b->len          = 0;
    b->curpos       = pad_left;
    b->capacity     = real_cap;
    b->l_pad        = pad_left;

    return b;
}

sbuf_t *sbufCreate(uint32_t minimum_capacity)
{
    return sbufCreateWithPadding(minimum_capacity, 0);
}

void sbufDuplicateTo(sbuf_t *b, sbuf_t *dest)
{

    if (b->curpos >= sbufGetTotalCapacity(dest))
    {
        printError("Buffer duplication failed: source buffer's current position exceeds destination buffer's total capacity.");
        return;
    }

    dest->curpos = b->curpos;

    uint32_t copy_length = min(sbufGetLength(b), sbufGetMaximumWriteableSize(dest));
    sbufSetLength(dest, copy_length);
    memoryCopyLarge(sbufGetMutablePtr(dest), sbufGetRawPtr(b), copy_length);
}

sbuf_t *sbufDuplicate(sbuf_t *b)
{
    sbuf_t *newbuf = sbufCreateWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);

    sbufDuplicateTo(b, newbuf);
    return newbuf;
}

sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict const buf)
{
    uint32_t root_length   = sbufGetLength(root);
    uint32_t append_length = sbufGetLength(buf);

    if (UNLIKELY(root_length > UINT32_MAX - append_length))
    {
        printError("sbuf: concat overflow (root=%u, append=%u)", root_length, append_length);
        terminateProgram(1);
    }

    root = sbufReserveSpace(root, root_length + append_length);
    sbufSetLength(root, root_length + append_length);

    memoryCopyLarge(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);

    return root;
}

sbuf_t *sbufMoveTo(sbuf_t *restrict dest, sbuf_t *restrict source, const uint32_t bytes)
{
    uint32_t dest_length = sbufGetLength(dest);

    assert(bytes <= sbufGetLength(source));
    assert(dest_length <= UINT32_MAX - bytes);
    assert(dest_length + bytes <= sbufGetMaximumWriteableSize(dest));

    memoryCopyLarge(sbufGetMutablePtr(dest) + dest_length, sbufGetRawPtr(source), bytes);
    sbufSetLength(dest, dest_length + bytes);

    sbufShiftRight(source, bytes);

    return dest;
}

sbuf_t *sbufSlice(sbuf_t *const b, const uint32_t bytes)
{
    sbuf_t *newbuf = sbufCreateWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);
    sbufMoveTo(newbuf, b, bytes);
    return newbuf;
}
