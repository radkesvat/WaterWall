#include "shiftbuffer.h"
#include "wlibc.h"

// #define LEFTPADDING  ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 10) : (1U << 8)) - (sizeof(uint32_t) * 3))
// #define RIGHTPADDING ((RAM_PROFILE >= kRamProfileS2Memory ? (1U << 9) : (1U << 7)))

// #define TOTALPADDING ((uint32_t) (sizeof(sbuf_t) + (LEFTPADDING + RIGHTPADDING)))

/**
 * Destroys the shift buffer and frees its memory.
 * @param b The shift buffer to destroy.
 */
void sbufDestroy(sbuf_t *b)
{
    memoryFree(b);
}

/**
 * Creates a new shift buffer with specified minimum capacity and left padding.
 * @param minimum_capacity The minimum capacity of the buffer.
 * @param pad_left The left padding of the buffer.
 * @return A pointer to the created shift buffer.
 */
sbuf_t *sbufNewWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    if (minimum_capacity != 0 && minimum_capacity % kCpuLineCacheSize != 0)
    {
        minimum_capacity = (max((uint32_t) kCpuLineCacheSize, minimum_capacity) + kCpuLineCacheSizeMin1) &
                           (uint32_t) ~kCpuLineCacheSizeMin1;
    }

    uint32_t real_cap = minimum_capacity + pad_left;
    sbuf_t  *b        = memoryAllocate(real_cap + 128);

    b->len      = 0;
    b->curpos   = pad_left;
    b->capacity = real_cap;
    b->l_pad    = pad_left;

    return b;
}

/**
 * Creates a new shift buffer with specified minimum capacity.
 * @param minimum_capacity The minimum capacity of the buffer.
 * @return A pointer to the created shift buffer.
 */
sbuf_t *sbufNew(uint32_t minimum_capacity)
{
    return sbufNewWithPadding(minimum_capacity, 0);
}

/**
 * Duplicates the given shift buffer.
 * @param b The shift buffer to duplicate.
 * @return A pointer to the duplicated shift buffer.
 */
sbuf_t *sbufDuplicate(sbuf_t *b)
{
    sbuf_t *newbuf = sbufNewWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);
    sbufSetLength(newbuf, sbufGetBufLength(b));
    memoryCopy128(sbufGetMutablePtr(newbuf), sbufGetRawPtr(b), sbufGetBufLength(b));

    return newbuf;
}

/**
 * Concatenates two shift buffers.
 * @param root The root shift buffer.
 * @param buf The buffer to concatenate to the root.
 * @return A pointer to the concatenated shift buffer.
 */
sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict const buf)
{
    uint32_t root_length   = sbufGetBufLength(root);
    uint32_t append_length = sbufGetBufLength(buf);
    root                   = sbufReserveSpace(root, root_length + append_length);
    sbufSetLength(root, root_length + append_length);

    memoryCopy128(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);

    return root;
}

/**
 * Moves data from the source buffer to the destination buffer.
 * @param dest The destination buffer.
 * @param source The source buffer.
 * @param bytes The number of bytes to move.
 * @return A pointer to the destination buffer.
 */
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

/**
 * Slices the given buffer by the specified number of bytes.
 * @param b The buffer to slice.
 * @param bytes The number of bytes to slice.
 * @return A pointer to the sliced buffer.
 */
sbuf_t *sbufSlice(sbuf_t *const b, const uint32_t bytes)
{
    sbuf_t *newbuf = sbufNewWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);
    sbufMoveTo(newbuf, b, bytes);
    return newbuf;
}
