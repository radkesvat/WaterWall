#include "startup_options.h"
#include "startup_windows.h"
#include <stdio.h>
#include <string.h>

#define CHECK(expression)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! (expression))                                                                                            \
        {                                                                                                              \
            fprintf(stderr, "check failed at %d: %s\n", __LINE__, #expression);                                        \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static HANDLE snapshot(size_t length, uint64_t declared, int writable_child, int reserve_tail)
{
    HANDLE writable = CreateFileMappingW(INVALID_HANDLE_VALUE,
                                         NULL,
                                         PAGE_READWRITE | (reserve_tail ? SEC_RESERVE : 0),
                                         0,
                                         (DWORD) (sizeof(waterwall_snapshot_header_t) + length),
                                         NULL);
    if (writable == NULL)
        return NULL;
    void *view = MapViewOfFile(writable, FILE_MAP_WRITE, 0, 0, 0);
    if (view == NULL)
    {
        CloseHandle(writable);
        return NULL;
    }
    if (reserve_tail && VirtualAlloc(view, sizeof(waterwall_snapshot_header_t), MEM_COMMIT, PAGE_READWRITE) == NULL)
    {
        UnmapViewOfFile(view);
        CloseHandle(writable);
        return NULL;
    }
    waterwall_snapshot_header_t header = {WW_SNAPSHOT_MAGIC, declared, ~declared};
    memcpy(view, &header, sizeof(header));
    if (! reserve_tail)
        memset((char *) view + sizeof(header), 'x', length);
    UnmapViewOfFile(view);
    HANDLE child = NULL;
    DuplicateHandle(GetCurrentProcess(),
                    writable,
                    GetCurrentProcess(),
                    &child,
                    FILE_MAP_READ | (writable_child ? FILE_MAP_WRITE : 0),
                    TRUE,
                    0);
    CloseHandle(writable);
    return child;
}

int main(void)
{
    for (int mode = 0; mode < 6; ++mode)
    {
        const size_t length  = 65537;
        HANDLE       mapping = snapshot(length, mode == 1 ? length - 1 : length, mode == 2, mode == 5);
        CHECK(mapping != NULL);
        char handle_arg[80];
        snprintf(handle_arg, sizeof(handle_arg), "--ww-internal-map=%llu", (unsigned long long) (uintptr_t) mapping);
        char               *argv[]  = {"fixture",
                                       handle_arg,
                                       "--ww-internal-len=65537",
                                       "--ww-internal-src=stdin",
                                       "--ww-internal-exe=C:\\outer folder\\Waterwall.exe",
                                       "--restricted-config",
                                       NULL};
        int                 argc    = 6;
        waterwall_handoff_t handoff = {0};
        CHECK(waterwallStartupHandoffExtract(&argc, argv, &handoff) == 1);
        CHECK(argc == 2 && strcmp(argv[1], "--restricted-config") == 0);
        if (mode == 3)
        {
            waterwallStartupHandoffCleanup(&handoff);
            DWORD flags;
            CHECK(! GetHandleInformation(mapping, &flags));
            continue;
        }
        if (mode == 4)
            handoff.length = SIZE_MAX;
        char  *content  = NULL;
        size_t received = 0;
        int    result   = waterwallStartupHandoffReceive(&handoff, false, &content, &received);
        CHECK((result == 0) == (mode == 0));
        CHECK(handoff.mapping == 0);
        DWORD flags;
        CHECK(! GetHandleInformation(mapping, &flags));
        if (result == 0)
        {
            CHECK(received == length && content[length] == 0);
            for (size_t i = 0; i < length; ++i)
                CHECK(content[i] == 'x');
            free(content);
        }
        waterwallStartupHandoffCleanup(&handoff);
    }
    char *bad_sets[][7] = {{"fixture",
                            "--ww-internal-map=18446744073709551615",
                            "--ww-internal-len=1",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=C:\\x",
                            NULL},
                           {"fixture",
                            "--ww-internal-map=16",
                            "--ww-internal-len=1",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=relative",
                            NULL},
                           {"fixture",
                            "--ww-internal-map=16",
                            "--ww-internal-map=16",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=C:\\x",
                            NULL},
                           {"fixture", "--ww-internal-map=16", "--ww-internal-len=1", "--ww-internal-src=x", NULL},
                           {"fixture",
                            "--ww-internal-map=+16",
                            "--ww-internal-len=1",
                            "--ww-internal-src=x",
                            "--ww-internal-exe=C:\\x",
                            NULL}};
    for (size_t i = 0; i < sizeof(bad_sets) / sizeof(bad_sets[0]); ++i)
    {
        int argc = 0;
        while (bad_sets[i][argc] != NULL)
            ++argc;
        waterwall_handoff_t handoff = {0};
        CHECK(waterwallStartupHandoffExtract(&argc, bad_sets[i], &handoff) == -1);
        waterwallStartupHandoffCleanup(&handoff);
    }
    /* Unlike POSIX descriptors, a Windows mapping may have handle value 4
     * when standard handles are absent. Parsing must not reserve that value. */
    char               *low_argv[] = {"fixture",
                                      "--ww-internal-map=4",
                                      "--ww-internal-len=1",
                                      "--ww-internal-src=stdin",
                                      "--ww-internal-exe=C:\\x",
                                      NULL};
    int                 low_argc   = 5;
    waterwall_handoff_t low        = {0};
    CHECK(waterwallStartupHandoffExtract(&low_argc, low_argv, &low) == 1 && low.mapping == 4);
    /* This is a numeric parser case, not an OS handle owned by the test. */
    low.mapping = 0;
    waterwallStartupHandoffCleanup(&low);
    puts("Windows handoff validation and handle ownership passed");
    return 0;
}
