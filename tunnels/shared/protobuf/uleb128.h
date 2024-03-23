#pragma once
#include <stdint.h>
#include <stddef.h>
/*

helper functions for unsigned little endian base 128  encode / decode

*/

/* Decode the unsigned LEB128 constant at BUF into the variable pointed to
   by R, and return the number of bytes read.
   If we read off the end of the buffer, zero is returned,
   and nothing is stored in R.

   Note: The result is an int instead of a pointer to the next byte to be
   read to avoid const-vs-non-const problems.  */

static inline size_t
read_uleb128_to_uint64(const unsigned char *buf, const unsigned char *buf_end,
                       uint64_t *r)
{
    const unsigned char *p = buf;
    unsigned int shift = 0;
    uint64_t result = 0;
    unsigned char byte;

    while (1)
    {
        if (p >= buf_end)
            return 0;

        byte = *p++;
        result |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0)
            break;
        shift += 7;
    }

    *r = result;
    return p - buf;
}


// writes and moves to right, use size_uleb128 to calculate the len before write
static inline void
write_uleb128(unsigned char *p, size_t val)
{
    unsigned char c;
    do
    {
        c = val & 0x7f;
        val >>= 7;
        if (val)
            c |= 0x80;
        *p++ = c;
    } while (val);
}


/**
 * Get size of unsigned LEB128 data
 * @val: value
 *
 * Determine the number of bytes required to encode an unsigned LEB128 datum.
 * The algorithm is taken from Appendix C of the DWARF 3 spec. For information
 * on the encodings refer to section "7.6 - Variable Length Data". Return
 * the number of bytes required.
 */
static inline size_t
size_uleb128(unsigned long val) {
  size_t count = 0;
  do {
    val >>= 7;
    ++count;
  } while (val != 0);
  return count;
}
