#define _GNU_SOURCE
#include "cJSON.h"
#include "config_lexical.h"
#include "launcher.h"
#include "packed_payload.h"
#include "startup_options.h"
#include "ww_xz_decoder.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! (x))                                                                                                     \
        {                                                                                                              \
            fprintf(stderr, "check failed: line %d: %s\n", __LINE__, #x);                                              \
            exit(2);                                                                                                   \
        }                                                                                                              \
    } while (0)

/* Mock payload metadata */
const unsigned char waterwallPackedBytes[]  = {0xFD, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x01};
const size_t        waterwallPackedLength   = 8;
const uint64_t      waterwallRuntimeLength  = 128;
const char          waterwallPackedTarget[] = "linux-x86_64";

static enum
{
    SIM_OK,
    SIM_OLD_KERNEL,
    SIM_MEMFD_DENIED,
    SIM_SIZE_FAIL,
    SIM_MAP_FAIL,
    SIM_DECODE_FAIL,
    SIM_INPUT_SEAL_FAIL,
    SIM_EXE_SEAL_FAIL,
    SIM_INHERIT_FAIL,
    SIM_WRITE_ZERO,
    SIM_EXEC_FAIL
} sim_failure;

static int    memfd_calls;
static int    descriptors_open;
static int    mappings_open;
static int    execveat_calls;
static int    input_fd_captured;
static size_t input_len_captured;
static char   captured_input_bytes[1024];
static size_t captured_input_length;
static bool   real_cloexec_observed;

int waterwallInnerMain(int argc, char **argv);

long __wrap_syscall(long number, ...)
{
    va_list args;
    va_start(args, number);

    if (number == SYS_memfd_create)
    {
        const char  *name  = va_arg(args, const char *);
        unsigned int flags = va_arg(args, unsigned int);
        va_end(args);

        (void) name;
        ++memfd_calls;

        if (strcmp(name, "waterwall-input") == 0)
        {
            /* Real or simulated input memfd */
            ++descriptors_open;
            return 4000;
        }

        /* Executable memfd */
        if (sim_failure == SIM_MEMFD_DENIED)
        {
            errno = EPERM;
            return -1;
        }
        if (sim_failure == SIM_OLD_KERNEL && (flags & 0x0010U) != 0)
        {
            errno = EINVAL;
            return -1;
        }
        ++descriptors_open;
        return 4095;
    }
    else if (number == SYS_execveat)
    {
        int          dirfd = va_arg(args, int);
        const char  *path  = va_arg(args, const char *);
        char *const *argv  = va_arg(args, char *const *);
        char *const *envp  = va_arg(args, char *const *);
        int          flags = va_arg(args, int);
        va_end(args);

        (void) dirfd;
        (void) path;
        (void) envp;
        (void) flags;

        ++execveat_calls;

        /* Verify handoff arguments passed in argv */
        CHECK(argv != NULL);
        bool has_fd = false, has_len = false, has_src = false, has_exe = false;
        for (int i = 1; argv[i] != NULL; ++i)
        {
            if (strncmp(argv[i], "--ww-internal-fd=", sizeof("--ww-internal-fd=") - 1) == 0)
            {
                has_fd            = true;
                input_fd_captured = atoi(argv[i] + sizeof("--ww-internal-fd=") - 1);
            }
            else if (strncmp(argv[i], "--ww-internal-len=", sizeof("--ww-internal-len=") - 1) == 0)
            {
                has_len            = true;
                input_len_captured = (size_t) strtoull(argv[i] + sizeof("--ww-internal-len=") - 1, NULL, 10);
            }
            else if (strncmp(argv[i], "--ww-internal-src=", sizeof("--ww-internal-src=") - 1) == 0)
            {
                has_src = true;
            }
            else if (strncmp(argv[i], "--ww-internal-exe=", sizeof("--ww-internal-exe=") - 1) == 0)
            {
                has_exe = true;
            }
        }
        CHECK(has_fd && has_len && has_src && has_exe);
        CHECK(input_fd_captured == 4000);

        if (sim_failure == SIM_EXEC_FAIL)
        {
            errno = EACCES;
            return -1;
        }

        errno = ENOEXEC;
        return -1;
    }

    va_end(args);
    return -1;
}

int __wrap_ftruncate(int fd, off_t size)
{
    (void) fd;
    (void) size;
    if (sim_failure == SIM_SIZE_FAIL)
    {
        errno = ENOSPC;
        return -1;
    }
    return 0;
}

void *__wrap_mmap(void *address, size_t size, int protection, int flags, int fd, off_t offset)
{
    (void) address;
    (void) protection;
    (void) flags;
    (void) fd;
    (void) offset;
    if (sim_failure == SIM_MAP_FAIL)
    {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    ++mappings_open;
    return malloc(size);
}

int __wrap_munmap(void *address, size_t size)
{
    (void) size;
    --mappings_open;
    free(address);
    return 0;
}

int __real_fcntl(int fd, int command, ...);

int __wrap_fcntl(int fd, int command, ...)
{
    va_list args;
    va_start(args, command);
    if (fd != 4000 && fd != 4095)
    {
        if (command == F_GETFD)
        {
            va_end(args);
            return __real_fcntl(fd, command);
        }
        CHECK(command == F_SETFD || command == F_ADD_SEALS || command == F_DUPFD_CLOEXEC);
        int value = va_arg(args, int);
        va_end(args);
        int result = __real_fcntl(fd, command, value);
        if (command == F_SETFD && result == 0 && (value & FD_CLOEXEC))
        {
            CHECK((__real_fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
            real_cloexec_observed = true;
        }
        return result;
    }
    if (command == F_ADD_SEALS)
    {
        int seals = va_arg(args, int);
        (void) seals;
        va_end(args);
        if ((sim_failure == SIM_INPUT_SEAL_FAIL && fd == 4000) || (sim_failure == SIM_EXE_SEAL_FAIL && fd == 4095))
        {
            errno = EPERM;
            return -1;
        }
        return 0;
    }
    if (command == F_DUPFD_CLOEXEC)
    {
        int min_fd = va_arg(args, int);
        va_end(args);
        return fd >= min_fd ? fd : min_fd;
    }
    if (command == F_GETFD)
    {
        va_end(args);
        return (fd == 4000 || fd == 4095) ? FD_CLOEXEC : 0;
    }
    if (command == F_SETFD)
    {
        va_end(args);
        if (sim_failure == SIM_INHERIT_FAIL)
        {
            errno = EIO;
            return -1;
        }
        return 0;
    }
    va_end(args);
    return 0;
}

extern ssize_t __real_write(int fd, const void *buf, size_t count);
extern off_t   __real_lseek(int fd, off_t offset, int whence);
extern int     __real_close(int fd);

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    if (fd == 4000)
    {
        if (sim_failure == SIM_WRITE_ZERO)
            return 0;
        CHECK(count <= sizeof(captured_input_bytes) - captured_input_length);
        memcpy(captured_input_bytes + captured_input_length, buf, count);
        captured_input_length += count;
        return (ssize_t) count;
    }
    return __real_write(fd, buf, count);
}

off_t __wrap_lseek(int fd, off_t offset, int whence)
{
    (void) offset;
    (void) whence;
    if (fd == 4000)
    {
        return 0;
    }
    return __real_lseek(fd, offset, whence);
}

int __wrap_close(int fd)
{
    if (fd == 4000 || fd == 4095)
    {
        if (descriptors_open > 0)
        {
            --descriptors_open;
        }
        return 0;
    }
    return __real_close(fd);
}

void wwXzDecoderInit(void)
{
}

ww_xz_result_t wwXzDecode(const void *input, size_t input_size, void *output, size_t output_capacity,
                          size_t expected_size)
{
    (void) input;
    (void) input_size;
    (void) output;
    (void) output_capacity;
    (void) expected_size;
    if (sim_failure == SIM_DECODE_FAIL)
    {
        return WW_XZ_INVALID_DATA;
    }
    return WW_XZ_OK;
}

static void resetSimulation(void)
{
    memfd_calls           = 0;
    descriptors_open      = 0;
    mappings_open         = 0;
    execveat_calls        = 0;
    input_fd_captured     = -1;
    input_len_captured    = 0;
    captured_input_length = 0;
    memset(captured_input_bytes, 0, sizeof(captured_input_bytes));
    sim_failure = SIM_OK;
}

static int runLauncherInput(const char *input, size_t length)
{
    FILE *stream = tmpfile();
    CHECK(stream != NULL);
    if (length > 0)
    {
        CHECK(fwrite(input, 1, length, stream) == length);
    }
    rewind(stream);
    CHECK(dup2(fileno(stream), STDIN_FILENO) >= 0);
    clearerr(stdin);

    char  program[] = "Waterwall";
    char  option[]  = "-c:stdin";
    char *args[]    = {program, option, NULL};
    int   status    = waterwallInnerMain(2, args);
    fclose(stream);
    return status;
}

static int runLauncherWithStdin(const char *input)
{
    return runLauncherInput(input, strlen(input));
}

extern long __real_syscall(long number, ...);

static void realSnapshotExec(void)
{
    int fd = (int) __real_syscall(SYS_memfd_create, "snapshot-test", 0U);
    CHECK(fd > 2);
    const size_t length = 128 * 1024;
    char        *bytes  = malloc(length);
    CHECK(bytes != NULL);
    memset(bytes, ' ', length);
    memcpy(bytes, "{}\0original", 11);
    CHECK(__real_write(fd, bytes, length) == (ssize_t) length);
    free(bytes);
    /* Receipt must start at zero even though this descriptor is at EOF. */
    char fd_arg[64], len_arg[64], pid_arg[64];
    snprintf(fd_arg, sizeof(fd_arg), "--ww-internal-fd=%d", fd);
    snprintf(len_arg, sizeof(len_arg), "--ww-internal-len=%zu", length);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0)
    {
        snprintf(pid_arg, sizeof(pid_arg), "%ld", (long) getpid());
        CHECK(setenv("WW_SNAPSHOT_TEST_PID", pid_arg, 1) == 0);
        char *args[] = {"snapshot-child",
                        fd_arg,
                        len_arg,
                        "--ww-internal-src=/removed/source.json",
                        "--ww-internal-exe=/original/Waterwall",
                        "--restricted-config",
                        NULL};
        execv("/proc/self/exe", args);
        _exit(3);
    }
    CHECK(__real_close(fd) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char **argv)
{
    if (strcmp(argv[0], "snapshot-child") == 0)
    {
        CHECK(getpid() == (pid_t) strtol(getenv("WW_SNAPSHOT_TEST_PID"), NULL, 10));
        waterwall_handoff_t handoff = {.fd = -1};
        CHECK(waterwallStartupHandoffExtract(&argc, argv, &handoff) == 1);
        CHECK(argc == 2 && strcmp(argv[1], "--restricted-config") == 0);
        CHECK(strcmp(handoff.source_name, "/removed/source.json") == 0);
        CHECK(strcmp(handoff.orig_exe, "/original/Waterwall") == 0);
        int    fd     = handoff.fd;
        char  *bytes  = NULL;
        size_t length = 0;
        CHECK(waterwallStartupHandoffReceive(&handoff, true, &bytes, &length) == 0);
        CHECK(length == 128 * 1024 && memcmp(bytes, "{}\0original", 11) == 0);
        for (size_t i = 11; i < length; ++i)
            CHECK(bytes[i] == ' ');
        CHECK(real_cloexec_observed);
        CHECK(lseek(fd, 0, SEEK_SET) == -1 && errno == EBADF);
        CHECK(! configLexicalCheckEncoding(bytes, length));
        waterwallStartupOptionsFreeCoreJson(bytes);
        waterwallStartupHandoffCleanup(&handoff);
        return 0;
    }
    realSnapshotExec();
    {
        struct stat before, after;
        CHECK(fstat(STDIN_FILENO, &before) == 0);
        waterwall_handoff_t empty = {0};
        waterwallStartupHandoffCleanup(&empty);
        CHECK(fstat(STDIN_FILENO, &after) == 0);
        CHECK(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
    }
    /* Invalid numeric handoffs must never wrap, allocate, or close stdin. */
    const char *bad_lengths[] = {"", "-1", "+1", " 1", "18446744073709551615", "18446744073709551616"};
    for (size_t i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); ++i)
    {
        char length_arg[96];
        snprintf(length_arg, sizeof(length_arg), "--ww-internal-len=%s", bad_lengths[i]);
        char               *args[]  = {"Waterwall",
                                       "--ww-internal-fd=10",
                                       length_arg,
                                       "--ww-internal-src=core.json",
                                       "--ww-internal-exe=/Waterwall",
                                       NULL};
        int                 count   = 5;
        waterwall_handoff_t handoff = {.fd = -1};
        CHECK(waterwallStartupHandoffExtract(&count, args, &handoff) == -1);
        waterwallStartupHandoffCleanup(&handoff);
    }

    /* 1. Version option: exits 0 without reading input or calling memfd */
    {
        resetSimulation();
        char  program[] = "Waterwall";
        char  version[] = "--version";
        char *args[]    = {program, version, NULL};
        CHECK(waterwallInnerMain(2, args) == 0);
        CHECK(memfd_calls == 0 && execveat_calls == 0);
    }

    /* 2. Bad option: exits nonzero without reading input or calling memfd */
    {
        resetSimulation();
        char  program[] = "Waterwall";
        char  bad[]     = "--unknown-argument";
        char *args[]    = {program, bad, NULL};
        CHECK(waterwallInnerMain(2, args) != 0);
        CHECK(memfd_calls == 0 && execveat_calls == 0);
    }

    /* 3. Outer boundary rejects reserved handoff arguments */
    {
        resetSimulation();
        char  program[] = "Waterwall";
        char  handoff[] = "--ww-internal-fd=5";
        char *args[]    = {program, handoff, NULL};
        CHECK(waterwallInnerMain(2, args) != 0);
        CHECK(memfd_calls == 0 && execveat_calls == 0);
    }

    /* 4. Section 6 Stage Boundary Examples */
    /* 4a. Basic validation failures: no restoration or exec attempted */
    const char *basic_failures[] = {
        "",          /* empty stdin */
        "{",         /* syntax error */
        "[1, 2]",    /* non-object root */
        "\"hello\"", /* string root */
        "123"        /* number root */
    };
    for (size_t i = 0; i < sizeof(basic_failures) / sizeof(basic_failures[0]); ++i)
    {
        resetSimulation();
        int status = runLauncherWithStdin(basic_failures[i]);
        CHECK(status != 0);
        CHECK(memfd_calls == 0);
        CHECK(execveat_calls == 0);
        CHECK(descriptors_open == 0);
        CHECK(mappings_open == 0);
    }

    /* 4b. Basic validation successes: restoration and exec attempted */
    const char *basic_successes[] = {
        "{}",
        "{\"configs\":[]}",
        "{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":1.5}}",
        "{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":2}}",
    };
    for (size_t i = 0; i < sizeof(basic_successes) / sizeof(basic_successes[0]); ++i)
    {
        resetSimulation();
        int status = runLauncherWithStdin(basic_successes[i]);
        CHECK(status != 0);
        CHECK(memfd_calls == 2); /* waterwall-input + waterwall */
        CHECK(execveat_calls == 1);
        CHECK(input_len_captured == strlen(basic_successes[i]));
    }

    {
        const char input[] = "{}\0original bytes after NUL";
        resetSimulation();
        CHECK(runLauncherInput(input, sizeof(input) - 1) != 0);
        CHECK(execveat_calls == 1 && captured_input_length == sizeof(input) - 1);
        CHECK(memcmp(captured_input_bytes, input, sizeof(input) - 1) == 0);
    }

    /* 5. Linux restoration and exec failure paths */
    for (int fail = SIM_OK; fail <= SIM_EXEC_FAIL; ++fail)
    {
        resetSimulation();
        sim_failure = fail;
        int status  = runLauncherWithStdin("{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":2}}");

        if (fail == SIM_OK || fail == SIM_OLD_KERNEL)
        {
            CHECK(status != 0);
            CHECK(execveat_calls == 1);
            if (fail == SIM_OLD_KERNEL)
            {
                /* 1 call for input + 2 calls for exe (with fallback) */
                CHECK(memfd_calls == 3);
            }
        }
        else
        {
            CHECK(status != 0);
            CHECK(descriptors_open == 0);
            CHECK(mappings_open == 0);
            CHECK(execveat_calls == (fail == SIM_EXEC_FAIL ? 1 : 0));
        }
    }

    /* The receiver rejects oversized restricted descriptors before allocation. */
    {
        int fd = (int) __real_syscall(SYS_memfd_create, "oversized-snapshot", 0U);
        CHECK(fd > 2);
        waterwall_handoff_t handoff = {.has_handoff = true, .fd = fd, .length = WW_HOST_CORE_JSON_LIMIT + 1};
        char               *bytes   = NULL;
        CHECK(waterwallStartupHandoffReceive(&handoff, true, &bytes, NULL) == -1);
        CHECK(bytes == NULL && handoff.fd == -1);
        CHECK(lseek(fd, 0, SEEK_SET) == -1 && errno == EBADF);
    }

    /* 6. Handoff extraction & receipt unit tests */
    {
        /* Complete handoff extraction */
        char  arg0[]      = "Waterwall";
        char  arg1[]      = "--ww-internal-fd=10";
        char  arg2[]      = "--ww-internal-len=15";
        char  arg3[]      = "--ww-internal-src=nodes.json";
        char  arg4[]      = "--ww-internal-exe=/usr/bin/Waterwall";
        char  arg5[]      = "--restricted-config";
        char *test_argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, NULL};
        int   test_argc   = 6;

        waterwall_handoff_t handoff     = {0};
        int                 extract_res = waterwallStartupHandoffExtract(&test_argc, test_argv, &handoff);
        CHECK(extract_res == 1);
        CHECK(test_argc == 2);
        CHECK(test_argv[0] == arg0);
        CHECK(test_argv[1] == arg5);
        CHECK(handoff.has_handoff);
        CHECK(handoff.fd == 10);
        CHECK(handoff.length == 15);
        CHECK(strcmp(handoff.source_name, "nodes.json") == 0);
        CHECK(strcmp(handoff.orig_exe, "/usr/bin/Waterwall") == 0);
        waterwallStartupHandoffCleanup(&handoff);
        CHECK(! handoff.has_handoff && handoff.source_name == NULL);
    }

    {
        /* Incomplete handoff rejection */
        char  arg0[]      = "Waterwall";
        char  arg1[]      = "--ww-internal-fd=10";
        char *test_argv[] = {arg0, arg1, NULL};
        int   test_argc   = 2;

        waterwall_handoff_t handoff     = {0};
        int                 extract_res = waterwallStartupHandoffExtract(&test_argc, test_argv, &handoff);
        CHECK(extract_res == -1);
        waterwallStartupHandoffCleanup(&handoff);
    }

    {
        /* Duplicate handoff rejection */
        char  arg0[]      = "Waterwall";
        char  arg1[]      = "--ww-internal-fd=10";
        char  arg2[]      = "--ww-internal-fd=11";
        char  arg3[]      = "--ww-internal-len=15";
        char  arg4[]      = "--ww-internal-src=nodes.json";
        char  arg5[]      = "--ww-internal-exe=/usr/bin/Waterwall";
        char *test_argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, NULL};
        int   test_argc   = 6;

        waterwall_handoff_t handoff     = {0};
        int                 extract_res = waterwallStartupHandoffExtract(&test_argc, test_argv, &handoff);
        CHECK(extract_res == -1);
        waterwallStartupHandoffCleanup(&handoff);
    }

    printf("packed_startup_test: checks passed.\n");
    return 0;
}
