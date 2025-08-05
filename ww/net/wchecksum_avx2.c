#include "wlibc.h"

uint16_t checksumAVX2(const void *, uint16_t, uint32_t);

// Note: This function works internally in big endian
uint16_t checksumAVX2(const void *addr, uint16_t len, uint32_t csum)
{
    csum = lwip_htons(csum);
    uint_fast64_t  acc       = csum; /* fixed size for asm */
    const uint8_t *buf       = (const uint8_t *) addr;
    uint16_t       remainder = 0; /* fixed size for endian swap */
    uint_fast16_t  count2;
    uint_fast16_t  count32;
    bool           is_odd;

    if (UNLIKELY(len == 0))
    {
        return (uint16_t) acc;
    }
    /* align first byte */
    is_odd = ((uintptr_t) buf & 1);
    if (UNLIKELY(is_odd))
    {
        ((uint8_t *) &remainder)[1] = *buf++;
        len--;
    }
    /* 256-bit, 32-byte stride */
    count32            = len >> 5;
    const __m256i zero = _mm256_setzero_si256();
    __m256i       sum  = zero;
    while (count32--)
    {
        __m256i tmp = _mm256_lddqu_si256((const __m256i *) buf); // load 256-bit blob

        __m256i lo = _mm256_unpacklo_epi16(tmp, zero);
        __m256i hi = _mm256_unpackhi_epi16(tmp, zero);

        sum = _mm256_add_epi32(sum, lo);
        sum = _mm256_add_epi32(sum, hi);
        buf += 32;
    }

    // add all 32-bit components together
    sum = _mm256_add_epi32(sum, _mm256_srli_si256(sum, 8));
    sum = _mm256_add_epi32(sum, _mm256_srli_si256(sum, 4));
#ifndef _MSC_VER
    acc += _mm256_extract_epi32(sum, 0) + _mm256_extract_epi32(sum, 4);
#else
    {
        __m128i __Y1 = _mm256_extractf128_si256(sum, 0 >> 2);
        __m128i __Y2 = _mm256_extractf128_si256(sum, 4 >> 2);
        acc += _mm_extract_epi32(__Y1, 0 % 4) + _mm_extract_epi32(__Y2, 4 % 4);
    }
#endif
    len %= 32;
    /* final 31 bytes */
    count2 = len >> 1;
    while (count2--)
    {
        acc += ((const uint16_t *) buf)[0];
        buf += 2;
    }
    /* trailing odd byte */
    if (len & 1)
    {
        ((uint8_t *) &remainder)[0] = *buf;
    }
    acc += remainder;
    acc = (acc >> 32) + (acc & 0xffffffff);
    acc = (acc >> 16) + (acc & 0xffff);
    acc = (acc >> 16) + (acc & 0xffff);
    acc += (acc >> 16);
    if (UNLIKELY(is_odd))
    {
        acc = ((acc & 0xff) << 8) | ((acc & 0xff00) >> 8);
    }
    return (uint16_t) ~acc;
}
