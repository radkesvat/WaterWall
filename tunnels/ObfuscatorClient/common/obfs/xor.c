#include "structure.h"

void obfuscatorclientXorByte(uint8_t *data, size_t size, uint8_t key)
{

#if HAVE_AVX2
    bool aligned = ((uintptr_t) data % 32 == 0);

    if (LIKELY(aligned))
    {
        // Assumes data is 32-byte aligned
        __m256i key_vec = _mm256_set1_epi8((char) key); // Replicate key across all 32 bytes
        size_t  i       = 0;

        // Process 32 bytes at a time using AVX2
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
    }
    else
    {
        __m256i key_vec = _mm256_set1_epi8((char) key); // Replicate key across all 32 bytes
        size_t  i       = 0;

        // Process 32 bytes at a time using AVX2
        for (; i + 32 <= size; i += 32)
        {
            __m256i data_vec = _mm256_loadu_si256((__m256i *) (data + i)); // Unaligned load
            __m256i result   = _mm256_xor_si256(data_vec, key_vec);        // XOR
            _mm256_storeu_si256((__m256i *) (data + i), result);           // Unaligned store
        }

        // Handle remaining bytes (< 32)
        for (; i < size; i++)
        {
            data[i] ^= key;
        }
    }
    
#else

#if WW_COMPILE_FOR_64BIT
    {
        bool aligned = ((uintptr_t) data % 8 == 0);

        if (aligned)
        {
            // Replicate key across 8 bytes (e.g., key=0xAB becomes 0xABABABABABABABAB)
            uint64_t  key64      = (uint64_t) key * 0x0101010101010101ULL;
            size_t    num_chunks = size / 8;
            uint64_t *data64     = (uint64_t *) data;

            // Process 8 bytes at a time
            for (size_t i = 0; i < num_chunks; i++)
            {
                data64[i] ^= key64;
            }

            // Handle remaining bytes (< 8)
            size_t remainder_start = num_chunks * 8;
            for (size_t i = remainder_start; i < size; i++)
            {
                data[i] ^= key;
            }
            return; // Early return after 64-bit processing
        }
    }
#endif

    // 32-bit fallback (or when 64-bit is not available/unaligned)
    bool aligned = ((uintptr_t) data % 4 == 0);

    if (aligned)
    {
        // Replicate key across 4 bytes (e.g., key=0xAB becomes 0xABABABAB)
        uint32_t  key32      = (uint32_t) key * 0x01010101U;
        size_t    num_chunks = size / 4;
        uint32_t *data32     = (uint32_t *) data;

        // Process 4 bytes at a time
        for (size_t i = 0; i < num_chunks; i++)
        {
            data32[i] ^= key32;
        }

        // Handle remaining bytes (< 4)
        size_t remainder_start = num_chunks * 4;
        for (size_t i = remainder_start; i < size; i++)
        {
            data[i] ^= key;
        }
    }
    else
    {
        // Fallback: byte-by-byte XOR for unaligned data
        for (size_t i = 0; i < size; i++)
        {
            data[i] ^= key;
        }
    }

#endif // HAVE_AVX2


}
