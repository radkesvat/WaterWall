#include "ww_xz_decoder.h"
#include <xz.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_file(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return NULL;
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return NULL;
    }
    long length = ftell(file);
    if (length < 0 || (unsigned long) length > SIZE_MAX - 16 || fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        return NULL;
    }
    *size               = (size_t) length;
    unsigned char *data = malloc(*size + 16);
    if (data == NULL)
    {
        fclose(file);
        return NULL;
    }
    size_t count  = fread(data, 1, *size, file);
    int    failed = ferror(file);
    if (fclose(file) != 0 || failed || count != *size)
    {
        free(data);
        return NULL;
    }
    return data;
}

static int expect(const char *label, ww_xz_result_t actual, ww_xz_result_t expected)
{
    if (actual == expected)
        return 0;
    fprintf(stderr, "%s: got %d, expected %d\n", label, actual, expected);
    return 1;
}

static void put_crc(unsigned char *target, const unsigned char *data, size_t size)
{
    uint32_t crc = xz_crc32(data, size, 0);
    for (unsigned int i = 0; i < 4; ++i)
        target[i] = (unsigned char) (crc >> (8 * i));
}

int main(int argc, char **argv)
{
    if (argc != 3)
        return 1;
    size_t         raw_size    = 0;
    size_t         packed_size = 0;
    unsigned char *raw         = read_file(argv[1], &raw_size);
    unsigned char *packed      = read_file(argv[2], &packed_size);
    unsigned char *output      = malloc(raw_size + 16);
    if (raw == NULL || packed == NULL || output == NULL)
    {
        free(raw);
        free(packed);
        free(output);
        return 1;
    }
    wwXzDecoderInit();
    memset(output, 0xa5, raw_size + 16);
    if (packed_size < 24 || memcmp(packed, "MUFASA", 6) != 0 || memcmp(packed + packed_size - 2, "gg", 2) != 0 ||
        packed[6] != 0 || packed[7] != 0xff || packed[packed_size - 4] != 0 || packed[packed_size - 3] != 0xff)
    {
        fputs("Unexpected Waterwall stream identifiers\n", stderr);
        free(raw);
        free(packed);
        free(output);
        return 1;
    }
    int failed = expect("roundtrip", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_OK);
    failed |= packed[7] != 0xff || packed[packed_size - 3] != 0xff; /* Input stays read-only. */
    failed |= memcmp(raw, output, raw_size) != 0;
    for (size_t i = raw_size; i < raw_size + 16; ++i)
        failed |= output[i] != 0xa5;
    failed |= expect("oversized expectation",
                     wwXzDecode(packed, packed_size, output, raw_size + 1, raw_size + 1),
                     WW_XZ_SIZE_MISMATCH);
    if (raw_size != 0)
    {
        failed |= expect(
            "small capacity", wwXzDecode(packed, packed_size, output, raw_size - 1, raw_size), WW_XZ_OUTPUT_TOO_SMALL);
        output[raw_size - 1] = 0xa5;
        failed |= expect("small expectation",
                         wwXzDecode(packed, packed_size, output, raw_size, raw_size - 1),
                         WW_XZ_OUTPUT_TOO_SMALL);
        failed |= output[raw_size - 1] != 0xa5;
    }
    /* Representative boundaries plus every truncation of the stream footer. */
    size_t cuts[] = {0, 1, 6, 11, 12, packed_size / 2};
    for (size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); ++i)
        failed |= wwXzDecode(packed, cuts[i], output, raw_size, raw_size) == WW_XZ_OK;
    for (size_t i = 1; i <= 12 && i <= packed_size; ++i)
        failed |= wwXzDecode(packed, packed_size - i, output, raw_size, raw_size) == WW_XZ_OK;

    packed[packed_size] = 0;
    failed |= expect(
        "trailing padding", wwXzDecode(packed, packed_size + 1, output, raw_size, raw_size), WW_XZ_TRAILING_DATA);
    if (packed_size <= SIZE_MAX / 2)
    {
        unsigned char *joined = malloc(packed_size * 2);
        if (joined == NULL)
            failed = 1;
        else
        {
            memcpy(joined, packed, packed_size);
            memcpy(joined + packed_size, packed, packed_size);
            failed |= expect("concatenated streams",
                             wwXzDecode(joined, packed_size * 2, output, raw_size, raw_size),
                             WW_XZ_TRAILING_DATA);
            free(joined);
        }
    }
    else
        failed = 1;
    if (packed_size >= 12)
    {
        /* Standard XZ and mixed identifiers must not pass the private decoder. */
        memcpy(packed, "\3757zXZ", 6);
        failed |=
            expect("standard header", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_INVALID_DATA);
        memcpy(packed + packed_size - 2, "YZ", 2);
        failed |=
            expect("standard magic", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_INVALID_DATA);
        memcpy(packed, "MUFASA", 6);
        failed |=
            expect("standard footer", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_INVALID_DATA);
        memcpy(packed + packed_size - 2, "gg", 2);
        packed[packed_size - 1] ^= 1;
        failed |=
            expect("corrupt footer", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_INVALID_DATA);
        packed[packed_size - 1] ^= 1;
        const unsigned char bad_checks[] = {0, 1, 4, 10, 0x80, 0xfe};
        for (size_t i = 0; i < sizeof(bad_checks); ++i)
        {
            packed[7] = bad_checks[i];
            failed |= expect("invalid header check marker",
                             wwXzDecode(packed, packed_size, output, raw_size, raw_size),
                             WW_XZ_UNSUPPORTED);
            packed[7]               = 0xff;
            packed[packed_size - 3] = bad_checks[i];
            failed |= expect("invalid footer check marker",
                             wwXzDecode(packed, packed_size, output, raw_size, raw_size),
                             WW_XZ_INVALID_DATA);
            packed[packed_size - 3] = 0xff;
        }
        /* CRCs must still be verified over the normalized flags, not 00 FF. */
        const size_t crc_offsets[] = {8, packed_size - 12};
        const size_t crc_inputs[]  = {6, packed_size - 8};
        const size_t crc_lengths[] = {2, 6};
        for (size_t i = 0; i < 2; ++i)
        {
            unsigned char saved[4];
            memcpy(saved, packed + crc_offsets[i], sizeof(saved));
            packed[crc_offsets[i]] ^= 1;
            failed |= expect(
                "corrupt stream CRC", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_INVALID_DATA);
            put_crc(packed + crc_offsets[i], packed + crc_inputs[i], crc_lengths[i]);
            failed |= expect("CRC over unnormalized flags",
                             wwXzDecode(packed, packed_size, output, raw_size, raw_size),
                             WW_XZ_INVALID_DATA);
            memcpy(packed + crc_offsets[i], saved, sizeof(saved));
        }
        packed[7] = 4;
        put_crc(packed + 8, packed + 6, 2);
        failed |=
            expect("CRC64 forbidden", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_UNSUPPORTED);
        packed[7] = 1;
        put_crc(packed + 8, packed + 6, 2);
        packed[7] = 0xff;
    }
    if (raw_size != 0)
    {
        /* The last block's CRC32 immediately precedes the stream index. */
        uint64_t index_size = 0;
        for (unsigned int i = 0; i < 4; ++i)
            index_size |= (uint64_t) packed[packed_size - 8 + i] << (8 * i);
        index_size = (index_size + 1) * 4;
        if (index_size > packed_size - 16)
            failed = 1;
        else
        {
            size_t check_offset = packed_size - 12 - (size_t) index_size - 4;
            packed[check_offset] ^= 1;
            failed |= expect("corrupt payload CRC32",
                             wwXzDecode(packed, packed_size, output, raw_size, raw_size),
                             WW_XZ_INVALID_DATA);
            packed[check_offset] ^= 1;
        }
        /* Assert actual encoder settings, then exercise the upstream filter
         * rejection with a valid block-header CRC. Empty XZ has no blocks. */
        if (packed_size < 24 || packed[12] != 2 || packed[13] != 1 || packed[14] != 4 || packed[15] != 0 ||
            packed[16] != 0x21 || packed[17] != 1 || packed[18] != 0x16)
        {
            fputs("Unexpected encoder filter chain or dictionary\n", stderr);
            failed = 1;
        }
        else
        {
            packed[14] = 7; /* ARM BCJ is unsupported by the shipped decoder. */
            put_crc(packed + 20, packed + 12, 8);
            failed |= expect("ARM BCJ", wwXzDecode(packed, packed_size, output, raw_size, raw_size), WW_XZ_UNSUPPORTED);
            packed[14] = 4;
            put_crc(packed + 20, packed + 12, 8);
            packed[packed_size / 2] ^= 0x40;
            failed |= wwXzDecode(packed, packed_size, output, raw_size, raw_size) == WW_XZ_OK;
            packed[packed_size / 2] ^= 0x40;
            /* A nondefault x86 BCJ start offset with a valid block header. */
            memmove(packed + 28, packed + 24, packed_size - 24);
            packed[12] = 3;
            packed[15] = 4;
            packed[16] = 0;
            packed[17] = 0x10;
            packed[18] = 0;
            packed[19] = 0;
            packed[20] = 0x21;
            packed[21] = 1;
            packed[22] = 0x16;
            packed[23] = 0;
            put_crc(packed + 24, packed + 12, 12);
            failed |= expect(
                "BCJ start offset", wwXzDecode(packed, packed_size + 4, output, raw_size, raw_size), WW_XZ_UNSUPPORTED);
        }
    }
    free(output);
    free(packed);
    free(raw);
    return failed ? 1 : 0;
}
