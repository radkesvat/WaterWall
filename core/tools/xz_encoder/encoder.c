#include "host_io.h"
#include "ww_xz_format.h"
#include <lzma.h>
#include <stdlib.h>

static int encode(FILE *input, FILE *output)
{
    lzma_options_bcj  bcj       = {.start_offset = 0};
    lzma_options_lzma lzma      = {.dict_size = 8U * 1024U * 1024U,
                                   .lc        = 3,
                                   .lp        = 0,
                                   .pb        = 2,
                                   .mode      = LZMA_MODE_NORMAL,
                                   .nice_len  = 64,
                                   .mf        = LZMA_MF_BT4,
                                   .depth     = 64};
    lzma_filter       filters[] = {{LZMA_FILTER_X86, &bcj}, {LZMA_FILTER_LZMA2, &lzma}, {LZMA_VLI_UNKNOWN, NULL}};
    lzma_stream       stream    = LZMA_STREAM_INIT;
    lzma_ret          result    = lzma_stream_encoder(&stream, filters, LZMA_CHECK_CRC32);
    if (result != LZMA_OK)
    {
        fprintf(stderr, "Cannot initialize XZ encoder (%d)\n", (int) result);
        lzma_end(&stream);
        return 1;
    }

    unsigned char in_buffer[65536];
    unsigned char out_buffer[65536];
    lzma_action   action = LZMA_RUN;
    int           failed = 1;
    for (;;)
    {
        if (stream.avail_in == 0 && action != LZMA_FINISH)
        {
            stream.next_in  = in_buffer;
            stream.avail_in = fread(in_buffer, 1, sizeof(in_buffer), input);
            if (ferror(input))
            {
                fputs("Cannot read input\n", stderr);
                break;
            }
            if (feof(input))
                action = LZMA_FINISH;
        }
        stream.next_out  = out_buffer;
        stream.avail_out = sizeof(out_buffer);
        result           = lzma_code(&stream, action);
        size_t count     = sizeof(out_buffer) - stream.avail_out;
        if (fwrite(out_buffer, 1, count, output) != count)
        {
            fputs("Cannot write output\n", stderr);
            break;
        }
        if (result == LZMA_STREAM_END)
        {
            failed = 0;
            break;
        }
        if (result != LZMA_OK)
        {
            fprintf(stderr, "XZ encoding failed (%d)\n", (int) result);
            break;
        }
    }
    lzma_end(&stream);
    return failed;
}

static int writeStreamIdentifiers(FILE *output)
{
    /* liblzma emits standard CRC32 XZ. Replace the magic and encode its CRC32
     * selector as FF in both copies of the stream flags. The decoder restores
     * 00 01 in its private buffers before checking the unchanged stream CRCs. */
    const unsigned char flags[2] = {0, WW_XZ_CRC32_MARKER};
    if (fseek(output, 0, SEEK_SET) != 0 ||
        fwrite(WW_XZ_HEADER_MAGIC, 1, WW_XZ_HEADER_MAGIC_SIZE, output) != WW_XZ_HEADER_MAGIC_SIZE ||
        fwrite(flags, 1, sizeof(flags), output) != sizeof(flags))
        return 1;
#ifdef _WIN32
    if (_fseeki64(output, -WW_XZ_FOOTER_MAGIC_SIZE - 2, SEEK_END) != 0)
#else
    if (fseeko(output, -WW_XZ_FOOTER_MAGIC_SIZE - 2, SEEK_END) != 0)
#endif
        return 1;
    return fwrite(flags, 1, sizeof(flags), output) != sizeof(flags) ||
           fwrite(WW_XZ_FOOTER_MAGIC, 1, WW_XZ_FOOTER_MAGIC_SIZE, output) != WW_XZ_FOOTER_MAGIC_SIZE;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fputs("Usage: waterwall_xz_encoder INPUT OUTPUT.xz\nOutput must not already exist.\n", stderr);
        return EXIT_FAILURE;
    }
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL)
    {
        perror("Cannot open input");
        return EXIT_FAILURE;
    }
    /* Exclusive creation also protects input when both paths identify it. */
    FILE *output = openExclusiveOutput(argv[2]);
    if (output == NULL)
    {
        perror("Cannot create output");
        fclose(input);
        return EXIT_FAILURE;
    }
    int failed = encode(input, output);
    if (! failed)
        failed = writeStreamIdentifiers(output);
    if (fclose(input) != 0)
        failed = 1;
    if (fclose(output) != 0)
        failed = 1;
    if (failed)
    {
        fputs("Encoding failed; removing incomplete output\n", stderr);
        if (remove(argv[2]) != 0)
            perror("Cannot remove incomplete output");
    }
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
