/* Build-time executable identification and C embedding. The OS is the loader. */
#include "host_io.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint16_t read16(const unsigned char *p)
{
    return (uint16_t) ((uint16_t) p[0] | (uint16_t) p[1] << 8);
}

static uint32_t read32(const unsigned char *p)
{
    return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24;
}

static int fileSize(FILE *file, uint64_t *size)
{
#ifdef _WIN32
    if (_fseeki64(file, 0, SEEK_END) != 0)
        return 0;
    __int64 end = _ftelli64(file);
#else
    if (fseeko(file, 0, SEEK_END) != 0)
        return 0;
    off_t end = ftello(file);
#endif
    if (end < 0 || fseek(file, 0, SEEK_SET) != 0)
        return 0;
    *size = (uint64_t) end;
    return 1;
}

static unsigned char *readImage(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        perror("Cannot open executable");
        return NULL;
    }
    uint64_t size;
    if (! fileSize(file, &size) || size == 0 || size > SIZE_MAX)
    {
        fputs("Cannot determine a usable executable size\n", stderr);
        fclose(file);
        return NULL;
    }
    unsigned char *data = malloc((size_t) size);
    if (data == NULL)
    {
        fputs("Cannot allocate executable input\n", stderr);
        fclose(file);
        return NULL;
    }
    int failed = fread(data, 1, (size_t) size, file) != (size_t) size;
    if (fclose(file) != 0)
        failed = 1;
    if (failed)
    {
        fputs("Cannot read executable\n", stderr);
        free(data);
        return NULL;
    }
    *length = (size_t) size;
    return data;
}

static int validateImage(const unsigned char *data, size_t length, const char *target)
{
    if (strcmp(target, "linux-x86_64") == 0)
    {
        return length >= 64 && memcmp(data, "\177ELF\002\001", 6) == 0 &&
               (read16(data + 16) == 2 || read16(data + 16) == 3) && read16(data + 18) == 62 &&
               (read32(data + 24) != 0 || read32(data + 28) != 0);
    }
    int x64 = strcmp(target, "windows-x86_64") == 0;
    if (length < 64 || memcmp(data, "MZ", 2) != 0)
        return 0;
    uint64_t pe = read32(data + 60);
    if (pe < 64 || pe > length - 24 || memcmp(data + (size_t) pe, "PE\0\0", 4) != 0)
        return 0;
    const unsigned char *coff          = data + (size_t) pe + 4;
    uint16_t             count         = read16(coff + 2);
    uint16_t             optional_size = read16(coff + 16);
    uint16_t             flags         = read16(coff + 18);
    uint64_t             optional      = pe + 24;
    uint64_t             sections      = optional + optional_size;
    if (read16(coff) != (x64 ? 0x8664 : 0x14c) || ! (flags & 2) || (flags & 0x2000) || count == 0 || count > 96 ||
        optional_size < (x64 ? 112 : 96) || sections + count * 40U > length)
        return 0;
    const unsigned char *header = data + (size_t) optional;
    if (read16(header) != (x64 ? 0x20b : 0x10b))
        return 0;
    uint32_t entry        = read32(header + 16);
    uint32_t image_size   = read32(header + 56);
    uint32_t headers_size = read32(header + 60);
    if (entry == 0 || entry >= image_size || sections + count * 40U > headers_size || headers_size > length)
        return 0;
    int executable_entry = 0;
    for (uint16_t i = 0; i < count; ++i)
    {
        const unsigned char *section      = data + (size_t) sections + i * 40U;
        uint32_t             virtual_size = read32(section + 8);
        uint32_t             address      = read32(section + 12);
        uint32_t             size         = read32(section + 16);
        uint32_t             offset       = read32(section + 20);
        uint64_t             extent       = virtual_size > size ? virtual_size : size;
        if (address + extent > image_size || address + extent > UINT32_MAX ||
            (size != 0 && (offset < headers_size || (uint64_t) offset + size > length)))
            return 0;
        if (address <= entry && entry < address + extent && (read32(section + 36) & 0x20000000))
            executable_entry = 1;
    }
    return executable_entry;
}

static int embed(const char *target, uint64_t raw_size, const char *input_path, const char *output_path)
{
    FILE *input = fopen(input_path, "rb");
    if (input == NULL)
    {
        perror("Cannot open compressed payload");
        return 1;
    }
    uint64_t size;
    if (! fileSize(input, &size) || size == 0)
    {
        fputs("Empty or unreadable compressed payload\n", stderr);
        fclose(input);
        return 1;
    }
    FILE *output = openExclusiveOutput(output_path);
    if (output == NULL)
    {
        perror("Cannot create payload source");
        fclose(input);
        return 1;
    }
    fputs("#include \"packed_payload.h\"\nconst unsigned char waterwallPackedBytes[] = {\n", output);
    unsigned char buffer[65536];
    uint64_t      written = 0;
    size_t        count;
    while ((count = fread(buffer, 1, sizeof(buffer), input)) != 0)
    {
        for (size_t i = 0; i < count; ++i)
        {
            fprintf(output, "%u,", (unsigned int) buffer[i]);
            if (++written % 24 == 0)
                fputc('\n', output);
        }
        if (ferror(output))
            break;
    }
    if (written % 24 != 0)
        fputc('\n', output);
    fprintf(output,
            "};\nconst size_t waterwallPackedLength = %" PRIu64 ";\n"
            "const uint64_t waterwallRuntimeLength = %" PRIu64 "ULL;\n"
            "const char waterwallPackedTarget[] = \"%s\";\n",
            size,
            raw_size,
            target);
    int failed = ferror(input) || ferror(output) || written != size;
    if (fclose(input) != 0)
        failed = 1;
    if (fclose(output) != 0)
        failed = 1;
    if (failed)
    {
        fputs("Cannot write complete payload source\n", stderr);
        if (remove(output_path) != 0)
            perror("Cannot remove incomplete payload source");
    }
    return failed;
}

int main(int argc, char **argv)
{
    if (! ((argc == 4 && strcmp(argv[1], "validate") == 0) || (argc == 6 && strcmp(argv[1], "embed") == 0)))
    {
        fputs("Usage: waterwall_payload_tool validate TARGET EXECUTABLE\n"
              "       waterwall_payload_tool embed TARGET EXECUTABLE PAYLOAD.xz OUTPUT.c\n",
              stderr);
        return EXIT_FAILURE;
    }
    if (strcmp(argv[2], "linux-x86_64") != 0 && strcmp(argv[2], "windows-x86_64") != 0 &&
        strcmp(argv[2], "windows-x86") != 0)
    {
        fputs("Unsupported payload target\n", stderr);
        return EXIT_FAILURE;
    }
    size_t         length;
    unsigned char *data = readImage(argv[3], &length);
    if (data == NULL)
        return EXIT_FAILURE;
    int valid = validateImage(data, length, argv[2]);
    free(data);
    if (! valid)
    {
        fprintf(stderr, "Invalid executable for payload target %s\n", argv[2]);
        return EXIT_FAILURE;
    }
    return argc == 4 ? EXIT_SUCCESS : embed(argv[2], (uint64_t) length, argv[4], argv[5]);
}
