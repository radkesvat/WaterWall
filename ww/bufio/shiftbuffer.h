#pragma once

/*
 * sbuf_t API for padded, shiftable byte buffers used across bufio components.
 */

#include "wlibc.h"

/*
    Buffer with length and capacity parameters.
    Designed for use with buffer_pool.h for efficient memory management.
    it will be aligned to 32 bytes boundary which will help memoryCopyAVX2 to use Aligned memory copy
*/

struct sbuf_s
{
    uint32_t curpos;
    uint32_t len;
    uint32_t capacity;
    uint16_t l_pad;        // constant when created, indicates how much bytes are available for switching left at the beginning
                           // something like leave-room in lwip pbuf

    bool     is_temporary; // if true, this buffer will not be freed or reused in pools (like stack buffer)
    
    uint8_t  _padding1;    // padding to align to 8 bytes

    MSVC_ATTR_ALIGNED_32 uint8_t buf[] GNU_ATTR_ALIGNED_32;
};

typedef struct sbuf_s sbuf_t;

#define SIZEOF_STRUCT_SBUF (sizeof(struct sbuf_s))

static_assert(SIZEOF_STRUCT_SBUF == 32, "sbuf_s size should be 32 bytes, buf array is flexible");

/**
 * @brief Copy a small byte range without relying on aligned copy routines.
 *
 * @param dst Destination memory.
 * @param src Source memory.
 * @param n Number of bytes to copy.
 */
static inline void sbufByteCopy(void *restrict dst, const void *restrict src, const uint32_t n)
{
    uint8_t       *d = (uint8_t *) dst;
    const uint8_t *s = (const uint8_t *) src;
    for (uint32_t i = 0; i < n; ++i)
    {
        d[i] = s[i];
    }
}

/**
 * @brief Align requested left padding to the allocator's internal boundary.
 *
 * @param pad_left Requested left padding in bytes.
 * @return uint16_t Aligned padding value.
 */
uint16_t sbufAlignLeftPadding(uint16_t pad_left);

/**
 * @brief Destroy a non-temporary buffer and free its allocation.
 *
 * @param b Buffer to destroy.
 */
void sbufDestroy(sbuf_t *b);

/**
 * @brief Reset a buffer for pool reuse.
 *
 * @param b Buffer to reset.
 */
static inline void sbufReset(sbuf_t *b)
{
    assert(! b->is_temporary);
    b->len    = 0;
    b->curpos = b->l_pad;
}

/**
 * @brief Create a new buffer with explicit payload capacity and left padding.
 *
 * @param minimum_capacity Minimum payload capacity excluding left padding.
 * @param pad_left Requested left padding in bytes.
 * @return sbuf_t* Newly allocated buffer.
 */
sbuf_t *sbufCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left);

/**
 * @brief Create a new buffer with zero left padding.
 *
 * @param minimum_capacity Minimum payload capacity.
 * @return sbuf_t* Newly allocated buffer.
 */
sbuf_t *sbufCreate(uint32_t minimum_capacity);

/**
 * @brief Append one buffer's payload to another.
 *
 * @param root Destination buffer that receives data.
 * @param buf Source buffer to append.
 * @return sbuf_t* Destination buffer (may be reallocated).
 */
sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict buf);

/**
 * @brief Move bytes from source payload head into destination tail.
 *
 * @param dest Destination buffer.
 * @param source Source buffer.
 * @param bytes Number of bytes to move.
 * @return sbuf_t* Destination buffer.
 */
sbuf_t *sbufMoveTo(sbuf_t *restrict dest, sbuf_t *restrict source, uint32_t bytes);

/**
 * @brief Extract a leading slice into a new buffer.
 *
 * @param b Source buffer.
 * @param bytes Number of bytes to slice.
 * @return sbuf_t* New buffer containing sliced bytes.
 */
sbuf_t *sbufSlice(sbuf_t *b, uint32_t bytes);

/**
 * @brief Duplicate a buffer including its padding configuration.
 *
 * @param b Source buffer.
 * @return sbuf_t* New duplicated buffer.
 */
sbuf_t *sbufDuplicate(sbuf_t *b);

/**
 * @brief Copy payload and cursor layout into an existing destination buffer.
 *
 * @param b Source buffer.
 * @param dest Destination buffer.
 */
void sbufDuplicateTo(sbuf_t *b, sbuf_t *dest);


/**
 * Gets total capacity of the buffer. (Total capacity is a constant value that will not change)
 */
static inline uint32_t sbufGetTotalCapacity(sbuf_t *const b)
{
    return b->capacity;
}

/**
 * Gets total capacity excluding padding.
 */
static inline uint32_t sbufGetTotalCapacityNoPadding(sbuf_t *const b)
{
    return b->capacity - (b->l_pad);
}

/**
 * Gets left capacity of the buffer. (This means how much space is left, it gets reduced if you shift left)
 */
static inline uint32_t sbufGetLeftCapacity(const sbuf_t *const b)
{
    return b->curpos;
}

/**
 * Gets left capacity excluding padding.
 */
static inline uint32_t sbufGetLeftCapacityNoPadding(const sbuf_t *const b)
{
    return b->curpos - b->l_pad;
}

/**
 * Gets the maximum total payload length that can be addressed from the current cursor.
 *
 * Important: this is not the spare growth available beyond the current payload length.
 * If you want to append `extra` bytes without moving `curpos`, compare against
 * `sbufGetLength(b) + extra` (or subtract the current length first).
 */
static inline uint32_t sbufGetMaximumWriteableSize(const sbuf_t *const b)
{
    return (b->capacity - b->curpos);
}

/**
 * Gets original value of left padding of the buffer (unchanged, not aligned to 32).
 */
static inline uint16_t sbufGetLeftPadding(const sbuf_t *const b)
{
    return b->l_pad;
}

/**
 * Shifts the buffer left by specified bytes.
 */
static inline void sbufShiftLeft(sbuf_t *const b, const uint32_t bytes)
{
    assert(sbufGetLeftCapacity(b) >= bytes);
    b->curpos -= bytes;
    b->len += bytes;
}

/**
 * Shifts the buffer right by specified bytes.
 */
static inline void sbufShiftRight(sbuf_t *const b, const uint32_t bytes)
{
    assert(b->len >= bytes);
    b->curpos += bytes;
    b->len -= bytes;
}

/**
 * Sets the length of the buffer.
 */
static inline void sbufSetLength(sbuf_t *const b, const uint32_t bytes)
{
    assert(b->curpos + bytes <= b->capacity);
    b->len = bytes;
}

/**
 * Gets the length of the buffer.
 */
static inline uint32_t sbufGetLength(const sbuf_t *const b)
{
    return b->len;
}

/**
 * Consumes specified bytes from the buffer.
 */
static inline void sbufConsume(sbuf_t *const b, const uint32_t bytes)
{
    assert(bytes <= b->len);
    sbufSetLength(b, sbufGetLength(b) - bytes);
}

/**
 * Gets raw pointer to buffer data.
 */
static inline const void *sbufGetRawPtr(const sbuf_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

/**
 * Gets mutable pointer to buffer data.
 */
static inline unsigned char *sbufGetMutablePtr(const sbuf_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

/**
 * Reads data from buffer into destination.
 */
static inline void sbufRead(const sbuf_t *const b, void *const dest, const uint32_t byte)
{
    memoryCopy(dest, sbufGetRawPtr(b), byte);
}

/**
 * Writes data to buffer from source.
 */
static inline void sbufWrite(sbuf_t *restrict const b, const void *restrict const buffer, const uint32_t len)
{
    memoryCopy(sbufGetMutablePtr(b), buffer, len);
}

/**
 * Writes data to buffer from source. but optimal for large buffers.
 */
static inline void sbufWriteLarge(sbuf_t *restrict const b, const void *restrict const buffer, const uint32_t len)
{
    memoryCopyLarge(sbufGetMutablePtr(b), buffer, len);
}

/**
 * Writes zeros to buffer.
 */
static inline void sbufWriteZeros(sbuf_t *restrict const b, const uint32_t len)
{
    memorySet(sbufGetMutablePtr(b), 0, len);
}

/**
 * Writes data from one buffer to another.
 */
static inline void sbufWriteBuf(sbuf_t *restrict const to, sbuf_t *restrict const from, uint32_t length)
{
    assert(sbufGetMaximumWriteableSize(to) >= length);
    memoryCopyLarge(sbufGetMutablePtr(to), sbufGetRawPtr(from), length);
}

/**
 * Reserves space in the buffer for specified bytes.
 */
static inline sbuf_t *sbufReserveSpace(sbuf_t *const b, const uint32_t bytes)
{
    uint32_t current_length = sbufGetLength(b);

    // `bytes` is the required writable size from current cursor, not an increment.
    if (sbufGetMaximumWriteableSize(b) < bytes)
    {
        uint32_t needed_writable = max(current_length, bytes);
        sbuf_t *bigger_buf       = sbufCreateWithPadding(needed_writable, b->l_pad);
        sbufSetLength(bigger_buf, current_length);
        sbufWriteBuf(bigger_buf, b, current_length);
        sbufDestroy(b);
        return bigger_buf;
    }
    return b;
}

/**
 * Concatenates two buffers without capacity check.
 */
static inline void sbufConcatNoCheck(sbuf_t *restrict root, const sbuf_t *restrict buf)
{
    uint32_t root_length   = sbufGetLength(root);
    uint32_t append_length = sbufGetLength(buf);
    sbufSetLength(root, root_length + append_length);
    memoryCopy(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);
}

/**
 * Writes a 8-bit unsigned integer.
 */
static inline void sbufWriteUI8(sbuf_t *const b, const uint8_t data)
{
    *sbufGetMutablePtr(b) = data;
}

/**
 * Reads a 8-bit unsigned integer.
 */
static inline uint8_t sbufReadUI8(const sbuf_t *const b)
{
    return *(uint8_t *) sbufGetRawPtr(b);
}

// UnAligned

/**
 * Reads an unaligned 16-bit unsigned integer.
 */
static inline void sbufReadUnAlignedUI16(const sbuf_t *const b, uint16_t *const dest)
{
    sbufByteCopy(dest, sbufGetRawPtr(b), (uint32_t) sizeof(*dest));
}

/**
 * Reads an unaligned 64-bit unsigned integer.
 */
static inline void sbufReadUnAlignedUI64(const sbuf_t *const b, uint64_t *const dest)
{
    sbufByteCopy(dest, sbufGetRawPtr(b), (uint32_t) sizeof(*dest));
}

/**
 * Writes an unaligned 32-bit signed integer.
 */
static inline void sbufWriteUnAlignedI32(sbuf_t *const b, const int32_t data)
{
    sbufByteCopy(sbufGetMutablePtr(b), &data, (uint32_t) sizeof(data));
}

/**
 * Writes an unaligned 32-bit unsigned integer.
 */
static inline void sbufWriteUnAlignedUI32(sbuf_t *const b, const uint32_t data)
{
    sbufByteCopy(sbufGetMutablePtr(b), &data, (uint32_t) sizeof(data));
}

/**
 * Writes an unaligned 16-bit signed integer.
 */
static inline void sbufWriteUnAlignedI16(sbuf_t *const b, const int16_t data)
{
    sbufByteCopy(sbufGetMutablePtr(b), &data, (uint32_t) sizeof(data));
}

/**
 * Writes an unaligned 16-bit unsigned integer.
 */
static inline void sbufWriteUnAlignedUI16(sbuf_t *const b, const uint16_t data)
{
    sbufByteCopy(sbufGetMutablePtr(b), &data, (uint32_t) sizeof(data));
}

// Aligned

/**
 * Reads an aligned 16-bit unsigned integer.
 */
static inline void sbufReadUI16(const sbuf_t *const b, uint16_t *const dest)
{
    *dest = *(uint16_t *) sbufGetRawPtr(b);
}

/**
 * Reads an aligned 64-bit unsigned integer.
 */
static inline void sbufReadUI64(const sbuf_t *const b, uint64_t *const dest)
{
    *dest = *(uint64_t *) sbufGetRawPtr(b);
}

/**
 * Writes an aligned 32-bit signed integer.
 */
static inline void sbufWriteI32(sbuf_t *const b, const int32_t data)
{
    *(int32_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Writes an aligned 32-bit unsigned integer.
 */
static inline void sbufWriteUI32(sbuf_t *const b, const uint32_t data)
{
    *(uint32_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Writes an aligned 16-bit signed integer.
 */
static inline void sbufWriteI16(sbuf_t *const b, const int16_t data)
{
    *(int16_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Writes an aligned 16-bit unsigned integer.
 */
static inline void sbufWriteUI16(sbuf_t *const b, const uint16_t data)
{
    *(uint16_t *) sbufGetMutablePtr(b) = data;
}

/**
 * Creates a temporary buffer from a pbuf, don't call sbufDestroy on this buffer.
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
 * @brief Duplicate and destroy a buffer in debug builds to catch stale usage.
 *
 * @param b Buffer to replace.
 * @return sbuf_t* Duplicated replacement buffer.
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
