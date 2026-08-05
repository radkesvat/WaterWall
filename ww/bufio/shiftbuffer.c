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
        abortProgramNow(1);
    }

    return (uint16_t) aligned_pad;
}

void sbufDestroy(sbuf_t *b)
{
    if (UNLIKELY(b->is_temporary))
    {
        return;
    }

    memoryFreeAligned(b);
}

sbuf_t *sbufCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    pad_left = sbufAlignLeftPadding(pad_left);

    /*
     * The rounding and the padding are both applied in 64-bit arithmetic by the
     * helper. Doing the cache-line round-up in 32-bit arithmetic first, as this
     * did, wraps for any request above UINT32_MAX - kCpuLineCacheSizeMin1: the
     * capacity collapsed to 0 and the "capacity overflow" check below it could
     * never fire, handing back a buffer of only pad_left bytes.
     *
     * Reaching this abort means a caller committed to a size that cannot exist.
     * There is no return value to fail through, and the request is already
     * nonsensical, so this is Category D. Callers holding an untrusted length
     * must pre-validate with sbufTryComputeCapacity() and fail locally instead.
     */
    uint32_t real_cap = 0;
    if (! sbufTryComputeCapacity(minimum_capacity, pad_left, &real_cap))
    {
        printError("sbuf: capacity overflow (minimum_capacity + pad_left)");
        abortProgramNow(1);
    }

    // Cannot wrap, and memoryAllocateAligned() cannot reject this for size: the
    // helper above accounted for the header and the alignment over-allocation,
    // which are the binding limits on 32-bit targets.
    size_t  total_size = sizeof(sbuf_t) + (size_t) real_cap;
    sbuf_t *b          = memoryAllocateAligned(total_size, kSbufAllocationAlignment);
    if (b == NULL)
    {
        printError("sbuf: allocation failed");
        exit(1);
    }

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

bool sbufDuplicateTo(const sbuf_t *b, sbuf_t *dest)
{
    assert(b != NULL && dest != NULL);

    const uint32_t source_curpos = b->curpos;
    const uint32_t source_length = sbufGetLength(b);
    const uint32_t dest_capacity = sbufGetTotalCapacity(dest);

    if (UNLIKELY(source_curpos > dest_capacity || source_length > dest_capacity - source_curpos))
    {
        return false;
    }

    dest->curpos = source_curpos;
    sbufSetLength(dest, source_length);
    if (source_length > 0)
    {
        memoryCopyLarge(sbufGetMutablePtr(dest), sbufGetRawPtr(b), source_length);
    }
    return true;
}

sbuf_t *sbufDuplicate(sbuf_t *b)
{
    sbuf_t *newbuf = sbufCreateWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);

    if (UNLIKELY(! sbufDuplicateTo(b, newbuf)))
    {
        sbufDestroy(newbuf);
        printError("sbuf: an exactly sized duplicate buffer could not represent its source");
        abortProgramNow(1);
    }
    return newbuf;
}

sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict const buf)
{
    uint32_t root_length   = sbufGetLength(root);
    uint32_t append_length = sbufGetLength(buf);

    if (UNLIKELY(root_length > UINT32_MAX - append_length))
    {
        printError("sbuf: concat overflow (root=%u, append=%u)", root_length, append_length);
        abortProgramNow(1);
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
