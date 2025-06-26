#pragma once

#include "wlibc.h"

/*

    This is just a buffer, with parameters like length, cap
    cap means the space you can still use without any cost (its preallocated space)


    This buffer is supposed to be taken out of a pool (buffer_pool.h)
    and some of the other useful functions are defined there


*/


struct sbuf_s
{
    uint32_t curpos;
    uint32_t len;
    uint32_t capacity;
    uint16_t l_pad;
    bool     is_temporary; // if true, this buffer will not be freed or reused in pools (like stack buffer)
    MSVC_ATTR_ALIGNED_16 uint8_t buf[] GNU_ATTR_ALIGNED_16;
};

typedef struct sbuf_s sbuf_t;

#define SIZEOF_STRUCT_SBUF (sizeof(struct sbuf_s))

static_assert(SIZEOF_STRUCT_SBUF == 16, "sbuf_s size is not 16 bytes, see above comment");

/**
 * Destroys the shift buffer and frees its memory.
 * @param b The shift buffer to destroy.
 */
void sbufDestroy(sbuf_t *b);

/**
 * Resets the shift buffer to its initial state.
 * useful when you are done with the buffer and want to reuse it (storing in pool again)
 * @param b The shift buffer to reset.
 */
static inline void sbufReset(sbuf_t *b)
{
    assert(!b->is_temporary);
    b->len          = 0;
    b->curpos       = b->l_pad;
    //capacity and left padding are fixed, so no need to reset them
    
}

/**
 * Creates a new shift buffer with specified minimum capacity and left padding.
 * @param minimum_capacity The minimum capacity of the buffer.
 * @param pad_left The left padding of the buffer.
 * @return A pointer to the created shift buffer.
 */
sbuf_t *sbufCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left);

/**
 * Creates a new shift buffer with specified minimum capacity.
 * @param minimum_capacity The minimum capacity of the buffer.
 * @return A pointer to the created shift buffer.
 */
sbuf_t *sbufCreate(uint32_t minimum_capacity);

/**
 * Concatenates two shift buffers.
 * @param root The root shift buffer.
 * @param buf The buffer to concatenate to the root.
 * @return A pointer to the concatenated shift buffer.
 */
sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict buf);

/**
 * Moves data from the source buffer to the destination buffer.
 * @param dest The destination buffer.
 * @param source The source buffer.
 * @param bytes The number of bytes to move.
 * @return A pointer to the destination buffer.
 */
sbuf_t *sbufMoveTo(sbuf_t *restrict dest, sbuf_t *restrict source, uint32_t bytes);

/**
 * Slices the given buffer by the specified number of bytes.
 * @param b The buffer to slice.
 * @param bytes The number of bytes to slice.
 * @return A pointer to the sliced buffer.
 */
sbuf_t *sbufSlice(sbuf_t *b, uint32_t bytes);

/**
 * Duplicates the given shift buffer.
 * @param b The shift buffer to duplicate.
 * @return A pointer to the duplicated shift buffer.
 */
sbuf_t *sbufDuplicate(sbuf_t *b);

/**
 * Gets the total capacity of the buffer.
 * @param b The buffer.
 * @return The total capacity of the buffer.
 */
static inline uint32_t sbufGetTotalCapacity(sbuf_t *const b)
{
    return b->capacity;
}

/**
 * Gets the total capacity of the buffer excluding padding.
 * @param b The buffer.
 * @return The total capacity of the buffer excluding padding.
 */
static inline uint32_t sbufGetTotalCapacityNoPadding(sbuf_t *const b)
{
    return b->capacity - (b->l_pad);
}

/**
 * Gets the left capacity of the buffer.
 * @param b The buffer.
 * @return The left capacity of the buffer.
 */
static inline uint32_t sbufGetLeftCapacity(const sbuf_t *const b)
{
    return b->curpos;
}

/**
 * Gets the left capacity of the buffer excluding padding.
 * @param b The buffer.
 * @return The left capacity of the buffer excluding padding.
 */
static inline uint32_t sbufGetLeftCapacityNoPadding(const sbuf_t *const b)
{
    return b->curpos - b->l_pad;
}

/**
 * Gets the right capacity of the buffer.
 * @param b The buffer.
 * @return The right capacity of the buffer.
 */
static inline uint32_t sbufGetRightCapacity(const sbuf_t *const b)
{
    return (b->capacity - b->curpos);
}

/**
 * Shifts the buffer to the left by the specified number of bytes.
 * @param b The buffer.
 * @param bytes The number of bytes to shift.
 */
static inline void sbufShiftLeft(sbuf_t *const b, const uint32_t bytes)
{

    assert(sbufGetLeftCapacity(b) >= bytes);

    b->curpos -= bytes;
    b->len += bytes;
}

/**
 * Shifts the buffer to the right by the specified number of bytes.
 * @param b The buffer.
 * @param bytes The number of bytes to shift.
 */
static inline void sbufShiftRight(sbuf_t *const b, const uint32_t bytes)
{
    assert(sbufGetRightCapacity(b) >= bytes);

    b->curpos += bytes;
    b->len -= bytes;
}

/**
 * Sets the length of the buffer.
 * @param b The buffer.
 * @param bytes The length to set.
 */
static inline void sbufSetLength(sbuf_t *const b, const uint32_t bytes)
{
    assert(sbufGetRightCapacity(b) >= bytes);
    b->len = bytes;
}

/**
 * Gets the length of the buffer.
 * @param b The buffer.
 * @return The length of the buffer.
 */
static inline uint32_t sbufGetLength(const sbuf_t *const b)
{
    return b->len;
}

/**
 * Consumes the specified number of bytes from the buffer.
 * @param b The buffer.
 * @param bytes The number of bytes to consume.
 */
static inline void sbufConsume(sbuf_t *const b, const uint32_t bytes)
{
    sbufSetLength(b, sbufGetLength(b) - bytes);
}

/**
 * Gets a raw pointer to the buffer data.
 * @param b The buffer.
 * @return A raw pointer to the buffer data.
 */
static inline const void *sbufGetRawPtr(const sbuf_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

/**
 * Gets a mutable pointer to the buffer data.
 * @param b The buffer.
 * @return A mutable pointer to the buffer data.
 */
static inline unsigned char *sbufGetMutablePtr(const sbuf_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

/**
 * Reads data from the buffer into the destination.
 * @param b The buffer.
 * @param dest The destination to read data into.
 * @param byte The number of bytes to read.
 */
static inline void sbufRead(const sbuf_t *const b, void *const dest, const uint32_t byte)
{
    memoryCopy(dest, sbufGetRawPtr(b), byte);
}

/**
 * Writes data to the buffer from the source.
 * @param b The buffer.
 * @param buffer The source data to write.
 * @param len The length of the data to write.
 */
static inline void sbufWrite(sbuf_t *restrict const b, const void *restrict const buffer, const uint32_t len)
{
    memoryCopy(sbufGetMutablePtr(b), buffer, len);
}

/**
 * Writes zeros to the buffer.
 * @param b The buffer.
 * @param len The length of the zeros to write.
 */
static inline void sbufWriteZeros(sbuf_t *restrict const b, const uint32_t len)
{
    memorySet(sbufGetMutablePtr(b), 0, len);
}

/**
 * Writes data from one buffer to another.
 * @param to The destination buffer.
 * @param from The source buffer.
 * @param length The length of the data to write.
 */
static inline void sbufWriteBuf(sbuf_t *restrict const to, sbuf_t *restrict const from, uint32_t length)
{
    assert(sbufGetRightCapacity(to) >= length);

    memoryCopy128(sbufGetMutablePtr(to), sbufGetRawPtr(from), length);
}

/**
 * Reserves space in the buffer for the specified number of bytes.
 * @param b The buffer.
 * @param bytes The number of bytes to reserve.
 * @return A pointer to the buffer with reserved space.
 */
static inline sbuf_t *sbufReserveSpace(sbuf_t *const b, const uint32_t bytes)
{
    if (sbufGetRightCapacity(b) < bytes)
    {
        sbuf_t *bigger_buf = sbufCreateWithPadding(sbufGetLength(b) + bytes, b->l_pad);
        sbufSetLength(bigger_buf, sbufGetLength(b));
        sbufWriteBuf(bigger_buf, b, sbufGetLength(b));
        sbufDestroy(b);
        return bigger_buf;
    }
    return b;
}

/**
 * Concatenates two buffers without checking capacity.
 * @param root The root buffer.
 * @param buf The buffer to concatenate to the root.
 */
static inline void sbufConcatNoCheck(sbuf_t *restrict root, const sbuf_t *restrict buf)
{
    uint32_t root_length   = sbufGetLength(root);
    uint32_t append_length = sbufGetLength(buf);
    sbufSetLength(root, root_length + append_length);
    memoryCopy(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);
}

// UnAligned

/**
 * Reads an unaligned 8-bit unsigned integer from the buffer.
 * @param b The buffer.
 * @param dest The destination to read the data into.
 */
static inline void sbufReadUnAlignedUI8(const sbuf_t *const b, uint8_t *const dest)
{
    memoryCopy(dest, sbufGetRawPtr(b), sizeof(*dest));
}

/**
 * Reads an unaligned 16-bit unsigned integer from the buffer.
 * @param b The buffer.
 * @param dest The destination to read the data into.
 */
static inline void sbufReadUnAlignedUI16(const sbuf_t *const b, uint16_t *const dest)
{
    memoryCopy(dest, sbufGetRawPtr(b), sizeof(*dest));
}

/**
 * Reads an unaligned 64-bit unsigned integer from the buffer.
 * @param b The buffer.
 * @param dest The destination to read the data into.
 */
static inline void sbufReadUnAlignedUI64(const sbuf_t *const b, uint64_t *const dest)
{
    memoryCopy(dest, sbufGetRawPtr(b), sizeof(*dest));
}

/**
 * Writes an unaligned 32-bit signed integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteUnAlignedI32(sbuf_t *const b, const int32_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

/**
 * Writes an unaligned 32-bit unsigned integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteUnAlignedUI32(sbuf_t *const b, const uint32_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

/**
 * Writes an unaligned 16-bit signed integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteUnAlignedI16(sbuf_t *const b, const int16_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

/**
 * Writes an unaligned 16-bit unsigned integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteUnAlignedUI16(sbuf_t *const b, const uint16_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

/**
 * Writes an unaligned 8-bit unsigned integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteUnAlignedUI8(sbuf_t *const b, const uint8_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

// Aligned

/**
 * Reads an aligned 8-bit unsigned integer from the buffer.
 * @param b The buffer.
 * @param dest The destination to read the data into.
 */
static inline void sbufReadUI8(const sbuf_t *const b, uint8_t *const dest)
{
    *dest = *(uint8_t *) sbufGetRawPtr(b);
}

/**
 * Reads an aligned 16-bit unsigned integer from the buffer.
 * @param b The buffer.
 * @param dest The destination to read the data into.
 */
static inline void sbufReadUI16(const sbuf_t *const b, uint16_t *const dest)
{
    *dest = *(uint16_t *) sbufGetRawPtr(b);
}

/**
 * Reads an aligned 64-bit unsigned integer from the buffer.
 * @param b The buffer.
 * @param dest The destination to read the data into.
 */
static inline void sbufReadUI64(const sbuf_t *const b, uint64_t *const dest)
{
    *dest = *(uint64_t *) sbufGetRawPtr(b);
}

/**
 * Writes an aligned 32-bit signed integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteI32(sbuf_t *const b, const int32_t data)
{
    *(int32_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Writes an aligned 32-bit unsigned integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteUI32(sbuf_t *const b, const uint32_t data)
{
    *(uint32_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Writes an aligned 16-bit signed integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteI16(sbuf_t *const b, const int16_t data)
{
    *(int16_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Writes an aligned 16-bit unsigned integer to the buffer.
 * @param b The buffer.
 * @param data The data to write.
 */
static inline void sbufWriteUI16(sbuf_t *const b, const uint16_t data)
{
    *(uint16_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Creates a Temporary buffer from a pbuf, make sure that dont call sbufDestroy on this buffer accidentally
 * @param p The pbuf to create a view from
 * @return A pointer to the created buffer.
 */
// static sbuf_t *sbufCreateViewFromPbuf(struct pbuf *p)
// {
//     if ((p->type_internal & PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS) != PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS)
//     {
//         return NULL;
//     }
//     // sbuf_t *temp_buf       = (sbuf_t *) (((uint8_t *) p->payload) - SIZEOF_STRUCT_SBUF);
//     sbuf_t *temp_buf       = (sbuf_t *) (&p->custom_data[0]);
//     temp_buf->is_temporary = true;
//     temp_buf->l_pad        = 0;
//     temp_buf->curpos       = ((uintptr_t) p->payload) - ((uintptr_t) temp_buf->buf);
//     temp_buf->len          = p->len;
//     temp_buf->capacity     = p->len;
//     if(p->len > 256){
//        printError("123132");
//     }
//     return temp_buf;
// }

#ifdef DEBUG

/**
 * Duplicates the buffer and destroys the original to catch use-after-free errors.
 * @param b The buffer to duplicate and destroy.
 * @return A pointer to the duplicated buffer.
 */
static sbuf_t *debugBufferWontBeReused(sbuf_t *b)
{
    sbuf_t *nbuf = sbufDuplicate(b);
    sbufDestroy(b);
    return nbuf;
}

#define BUFFER_WONT_BE_REUSED(x) ((x) = debugBufferWontBeReused(x))

#else

#define BUFFER_WONT_BE_REUSED(x)

#endif
