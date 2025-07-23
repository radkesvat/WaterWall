#include "shiftbuffer.h"
#include "wlibc.h"

// #define LEFTPADDING  ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 10) : (1U << 8)) - (sizeof(uint32_t) * 3))
// #define RIGHTPADDING ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 9) : (1U << 7)))

// #define TOTALPADDING ((uint32_t) (sizeof(sbuf_t) + (LEFTPADDING + RIGHTPADDING)))

/**
 * Destroys the shift buffer and frees its memory.
 */
void sbufDestroy(sbuf_t *b)
{
    if (UNLIKELY(b->is_temporary))
    {
        return;
    }
    
    memoryFree(b->original_ptr);
}

/**
 * Creates a new shift buffer with specified capacity and left padding.
 */
sbuf_t *sbufCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    // Ensure pad_left is always a multiple of 32 for optimal alignment
    pad_left = (pad_left + 31) & ~31;

    if (minimum_capacity != 0 && minimum_capacity % kCpuLineCacheSize != 0)
    {
        minimum_capacity =
            (max(kCpuLineCacheSize, minimum_capacity) + kCpuLineCacheSizeMin1) & (~kCpuLineCacheSizeMin1);
    }

    uint32_t real_cap = minimum_capacity + pad_left;
    
    size_t total_size = real_cap + sizeof(sbuf_t) + 31;
    void *raw_ptr = memoryAllocate(total_size);
    
    sbuf_t *b = (sbuf_t *)ALIGN2(raw_ptr, 32);
    
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

/**
 * Creates a new shift buffer with specified capacity.
 */
sbuf_t *sbufCreate(uint32_t minimum_capacity)
{
    return sbufCreateWithPadding(minimum_capacity, 0);
}

/**
 * Duplicates the shift buffer.
 */
sbuf_t *sbufDuplicate(sbuf_t *b)
{
    sbuf_t *newbuf = sbufCreateWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);
    sbufSetLength(newbuf, sbufGetLength(b));
    memoryCopyLarge(sbufGetMutablePtr(newbuf), sbufGetRawPtr(b), sbufGetLength(b));

    return newbuf;
}

/**
 * Concatenates two shift buffers.
 */
sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict const buf)
{
    uint32_t root_length   = sbufGetLength(root);
    uint32_t append_length = sbufGetLength(buf);
    root                   = sbufReserveSpace(root, root_length + append_length);
    sbufSetLength(root, root_length + append_length);

    memoryCopyLarge(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);

    return root;
}

/**
 * Moves data from source buffer to destination buffer.
 */
sbuf_t *sbufMoveTo(sbuf_t *restrict dest, sbuf_t *restrict source, const uint32_t bytes)
{
    assert(bytes <= sbufGetLength(source));
    assert(sbufGetLength(dest) == 0);

    dest = sbufReserveSpace(dest, bytes);
    sbufSetLength(dest, bytes);

    sbufWriteBuf(dest, source, bytes);

    sbufShiftRight(source, bytes);

    return dest;
}

/**
 * Slices the buffer by specified number of bytes.
 */
sbuf_t *sbufSlice(sbuf_t *const b, const uint32_t bytes)
{
    sbuf_t *newbuf = sbufCreateWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);
    sbufMoveTo(newbuf, b, bytes);
    return newbuf;
}
