#include <lzma.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#endif

static FILE *openExclusiveOutput(const char *path)
{
#ifdef _WIN32
    /* The legacy MSVCRT used by MinGW does not support fopen's C11 "x" mode. */
    int fd = _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
    if (fd == -1)
        return NULL;
    FILE *output = _fdopen(fd, "wb");
    if (output == NULL)
    {
        int saved_error = errno;
        _close(fd);
        remove(path);
        errno = saved_error;
    }
    return output;
#else
    return fopen(path, "wbx");
#endif
}

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
