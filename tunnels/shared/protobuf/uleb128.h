#pragma once
#include <stddef.h>
#include <stdint.h>

/*

    helper functions for unsigned little endian base 128  encode / decode

*/

//    decode the unsigned LEB128 value located at BUF into the result
//    normal: returns the number of bytes read.
//    fail: returns 0 if the buffer size is insufficent
static inline size_t readUleb128ToUint64(const unsigned char *restrict buffer_start,
                                         const unsigned char *restrict buffer_end, uint64_t *restrict result)
{
    const unsigned char *p     = buffer_start;
    unsigned int         shift = 0;
    uint64_t             final = 0;
    unsigned char        byte;

    while (1)
    {
        if (p >= buffer_end)
        {
            return 0;
        }

        byte = *p++;
        final |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0)
        {
            break;
        }
        shift += 7;
    }

    *result = final;
    return p - buffer_start;
}

// writes and moves to right, use size_uleb128 to calculate the len before write
static inline void writeUleb128(unsigned char *p, size_t val)
{
    unsigned char c;
    do
    {
        c = val & 0x7f;
        val >>= 7;
        if (val)
        {
            c |= 0x80;
        }
        *p++ = c;
    } while (val);
}

// Get size of unsigned LEB128 data
// calculate the number of bytes required to encode an unsigned LEB128 value.
static inline size_t sizeUleb128(unsigned long val)
{
    size_t count = 0;
    do
    {
        val >>= 7;
        ++count;
    } while (val != 0);
    return count;
}
