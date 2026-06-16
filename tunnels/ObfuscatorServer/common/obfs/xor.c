#include "structure.h"

void obfuscatorserverXorByte(uint8_t *data, size_t size, uint8_t key)
{
    // Strategy: peel the few unaligned leading bytes one at a time until the
    // pointer is aligned to the widest chunk, run the aligned wide loop over the
    // bulk, then finish the trailing bytes. This keeps the fast path active even
    // when the payload does not start on an aligned boundary, instead of
    // degrading the whole buffer to a narrower (or byte-by-byte) path.
    size_t i = 0;

#if HAVE_AVX2

    // Peel leading bytes until 32-byte aligned.
    size_t head = (size_t) ((32U - ((uintptr_t) data & 31U)) & 31U);
    if (head > size)
    {
        head = size;
    }
    for (; i < head; i++)
    {
        data[i] ^= key;
    }

    __m256i key_vec = _mm256_set1_epi8((char) key); // Replicate key across all 32 bytes

    // Process 32 bytes at a time using AVX2 (now guaranteed aligned)
    for (; i + 32 <= size; i += 32)
    {
        __m256i data_vec = _mm256_load_si256((__m256i *) (data + i)); // Aligned load
        __m256i result   = _mm256_xor_si256(data_vec, key_vec);       // XOR
        _mm256_store_si256((__m256i *) (data + i), result);           // Aligned store
    }

    // Handle remaining bytes (< 32)
    for (; i < size; i++)
    {
        data[i] ^= key;
    }

#elif WW_COMPILE_FOR_64BIT

    // Peel leading bytes until 8-byte aligned.
    size_t head = (size_t) ((8U - ((uintptr_t) data & 7U)) & 7U);
    if (head > size)
    {
        head = size;
    }
    for (; i < head; i++)
    {
        data[i] ^= key;
    }

    // Replicate key across 8 bytes (e.g., key=0xAB becomes 0xABABABABABABABAB)
    uint64_t  key64      = (uint64_t) key * 0x0101010101010101ULL;
    uint64_t *data64     = (uint64_t *) (data + i);
    size_t    num_chunks = (size - i) / 8;

    // Process 8 bytes at a time (now guaranteed aligned)
    for (size_t c = 0; c < num_chunks; c++)
    {
        data64[c] ^= key64;
    }
    i += num_chunks * 8;

    // Handle remaining bytes (< 8)
    for (; i < size; i++)
    {
        data[i] ^= key;
    }

#else

    // 32-bit build: peel leading bytes until 4-byte aligned.
    size_t head = (size_t) ((4U - ((uintptr_t) data & 3U)) & 3U);
    if (head > size)
    {
        head = size;
    }
    for (; i < head; i++)
    {
        data[i] ^= key;
    }

    // Replicate key across 4 bytes (e.g., key=0xAB becomes 0xABABABAB)
    uint32_t  key32      = (uint32_t) key * 0x01010101U;
    uint32_t *data32     = (uint32_t *) (data + i);
    size_t    num_chunks = (size - i) / 4;

    // Process 4 bytes at a time (now guaranteed aligned)
    for (size_t c = 0; c < num_chunks; c++)
    {
        data32[c] ^= key32;
    }
    i += num_chunks * 4;

    // Handle remaining bytes (< 4)
    for (; i < size; i++)
    {
        data[i] ^= key;
    }

#endif // HAVE_AVX2
}
