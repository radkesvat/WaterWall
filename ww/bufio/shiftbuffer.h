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

    uint8_t buf[] __attribute__((aligned(16)));
};

typedef struct sbuf_s sbuf_t;

void    sbufDestroy(sbuf_t *b);
sbuf_t *sbufNewWithPadding(uint32_t minimum_capacity, uint16_t pad_left);
sbuf_t *sbufNew(uint32_t minimum_capacity);
sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict buf);
sbuf_t *sbufMoveTo(sbuf_t *restrict dest, sbuf_t *restrict source, uint32_t bytes);
sbuf_t *sbufSlice(sbuf_t *b, uint32_t bytes);
sbuf_t *sbufDuplicate(sbuf_t *b);

static inline uint32_t sbufGetTotalCapacity(sbuf_t *const b)
{
    return b->capacity;
}

static inline uint32_t sbufGetTotalCapacityNoPadding(sbuf_t *const b)
{
    assert(((uint32_t) b->l_pad) >= b->capacity);

    return b->capacity - ((uint32_t) b->l_pad);
}

// caps mean how much memory we own to be able to shift left/right
static inline uint32_t sbufGetLeftCapacity(const sbuf_t *const b)
{
    return b->curpos;
}

static inline uint32_t sbufGetLeftCapacityNoPadding(const sbuf_t *const b)
{
    return b->curpos - b->l_pad;
}

static inline uint32_t sbufGetRightCapacity(const sbuf_t *const b)
{
    return (b->capacity - b->curpos);
}

static inline void sbufShiftLeft(sbuf_t *const b, const uint32_t bytes)
{

    assert(sbufGetLeftCapacity(b) >= bytes);

    b->curpos -= bytes;
    b->len += bytes;
}

static inline void sbufShiftRight(sbuf_t *const b, const uint32_t bytes)
{
    assert(sbufGetRightCapacity(b) >= bytes);

    b->curpos += bytes;
    b->len -= bytes;
}

// developer should call this function or reserve function before writing
static inline void sbufSetLength(sbuf_t *const b, const uint32_t bytes)
{
    assert(sbufGetRightCapacity(b) >= bytes);
    b->len = bytes;
}

static inline uint32_t sbufGetBufLength(const sbuf_t *const b)
{
    return b->len;
}

static inline void sbufConsume(sbuf_t *const b, const uint32_t bytes)
{
    sbufSetLength(b, sbufGetBufLength(b) - bytes);
}

static inline const void *sbufGetRawPtr(const sbuf_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

static inline unsigned char *sbufGetMutablePtr(const sbuf_t *const b)
{
    return (void *) &(b->buf[b->curpos]);
}

static inline void sbufRead(const sbuf_t *const b, void *const dest, const uint32_t byte)
{
    memoryCopy(dest, sbufGetRawPtr(b), byte);
}

static inline void sbufWrite(sbuf_t *restrict const b, const void *restrict const buffer, const uint32_t len)
{
    memoryCopy(sbufGetMutablePtr(b), buffer, len);
}

static inline void sbufWriteBuf(sbuf_t *restrict const to, sbuf_t *restrict const from, uint32_t length)
{
    assert(sbufGetRightCapacity(to) >= length);

    memoryCopy128(sbufGetMutablePtr(to), sbufGetRawPtr(from), length);

}

static inline sbuf_t *sbufReserveSpace(sbuf_t *const b, const uint32_t bytes)
{
    if (sbufGetRightCapacity(b) < bytes)
    {
        sbuf_t *bigger_buf = sbufNewWithPadding(sbufGetBufLength(b) + bytes, b->l_pad);
        sbufSetLength(bigger_buf, sbufGetBufLength(b));
        sbufWriteBuf(bigger_buf, b, sbufGetBufLength(b));
        sbufDestroy(b);
        return bigger_buf;
    }
    return b;
}


static inline void sbufConcatNoCheck(sbuf_t *restrict root, const sbuf_t *restrict buf)
{
    uint32_t root_length   = sbufGetBufLength(root);
    uint32_t append_length = sbufGetBufLength(buf);
    sbufSetLength(root, root_length + append_length);
    memoryCopy(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);
}

// UnAligned

static inline void sbufReadUnAlignedUI8(const sbuf_t *const b, uint8_t *const dest)
{
    memoryCopy(dest, sbufGetRawPtr(b), sizeof(*dest));
}

static inline void sbufReadUnAlignedUI16(const sbuf_t *const b, uint16_t *const dest)
{
    memoryCopy(dest, sbufGetRawPtr(b), sizeof(*dest));
}

static inline void sbufReadUnAlignedUI64(const sbuf_t *const b, uint64_t *const dest)
{
    memoryCopy(dest, sbufGetRawPtr(b), sizeof(*dest));
}

static inline void sbufWriteUnAlignedI32(sbuf_t *const b, const int32_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

static inline void sbufWriteUnAlignedUI32(sbuf_t *const b, const uint32_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

static inline void sbufWriteUnAlignedI16(sbuf_t *const b, const int16_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

static inline void sbufWriteUnAlignedUI16(sbuf_t *const b, const uint16_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

static inline void sbufWriteUnAlignedUI8(sbuf_t *const b, const uint8_t data)
{
    memoryCopy(sbufGetMutablePtr(b), &data, sizeof(data));
}

// Aligned

static inline void sbufReadUI8(const sbuf_t *const b, uint8_t *const dest)
{
    *dest = *(uint8_t *) sbufGetRawPtr(b);
}

static inline void sbufReadUI16(const sbuf_t *const b, uint16_t *const dest)
{
    *dest = *(uint16_t *) sbufGetRawPtr(b);
}

static inline void sbufReadUI64(const sbuf_t *const b, uint64_t *const dest)
{
    *dest = *(uint64_t *) sbufGetRawPtr(b);
}

static inline void sbufWriteI32(sbuf_t *const b, const int32_t data)
{
    *(int32_t *) sbufGetMutablePtr(b) = data;
}

static inline void sbufWriteUI32(sbuf_t *const b, const uint32_t data)
{
    *(uint32_t *) sbufGetMutablePtr(b) = data;
}

static inline void sbufWriteI16(sbuf_t *const b, const int16_t data)
{
    *(int16_t *) sbufGetMutablePtr(b) = data;
}

static inline void sbufWriteUI16(sbuf_t *const b, const uint16_t data)
{
    *(uint16_t *) sbufGetMutablePtr(b) = data;
}

#ifdef DEBUG

// free and re create the buffer so in case of use after free we catch it
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
