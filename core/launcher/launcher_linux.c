#define _GNU_SOURCE
#include "launcher.h"
#include "packed_payload.h"
#include "ww_xz_decoder.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS   1033
#define F_SEAL_SEAL   0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW   0x0004
#define F_SEAL_WRITE  0x0008
#endif

static int reserveAboveStandard(int fd)
{
    if (fd >= 0 && fd <= 2)
    {
        int higher      = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        int saved_error = errno;
        close(fd);
        errno = saved_error;
        return higher;
    }
    return fd;
}

static int launcherLinuxCreateSealedInputSnapshot(const char *buffer, size_t length)
{
    int fd = (int) syscall(SYS_memfd_create, "waterwall-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0)
    {
        return -1;
    }
    fd = reserveAboveStandard(fd);
    if (fd < 0)
    {
        return -1;
    }

    size_t written = 0;
    while (written < length)
    {
        ssize_t n = write(fd, buffer + written, length - written);
        if (n <= 0)
        {
            if (n < 0 && errno == EINTR)
                continue;
            int saved_error = n == 0 ? EIO : errno;
            close(fd);
            errno = saved_error;
            return -1;
        }
        written += (size_t) n;
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0)
    {
        close(fd);
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int launcherLinuxCaptureExecutablePath(char *buf, size_t size)
{
    ssize_t n = readlink("/proc/self/exe", buf, size);
    if (n < 0 || (size_t) n == size)
    {
        return -1;
    }
    buf[n] = '\0';
    return 0;
}

static int launcherLinuxRestoreAndExec(int input_fd, size_t input_len, const char *input_src, const char *orig_exe,
                                       int argc, char *const argv[])
{
    if (strcmp(waterwallPackedTarget, "linux-x86_64") != 0 || waterwallPackedLength == 0 ||
        waterwallRuntimeLength == 0 || waterwallRuntimeLength > SIZE_MAX || waterwallRuntimeLength > INT64_MAX)
    {
        fprintf(stderr, "Packed runtime: invalid payload metadata\n");
        return 1;
    }

    int exe_fd = (int) syscall(SYS_memfd_create, "waterwall", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
    /* Older kernels reject the new flag. Policy denials must not be retried. */
    if (exe_fd < 0 && errno == EINVAL)
    {
        exe_fd = (int) syscall(SYS_memfd_create, "waterwall", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    }
    if (exe_fd < 0)
    {
        fprintf(stderr, "Packed runtime: memfd_create failed: %s\n", strerror(errno));
        return 1;
    }
    exe_fd = reserveAboveStandard(exe_fd);
    if (exe_fd < 0)
    {
        return 1;
    }

    const size_t length = (size_t) waterwallRuntimeLength;
    if (ftruncate(exe_fd, (off_t) length) != 0)
    {
        fprintf(stderr, "Packed runtime: ftruncate failed: %s\n", strerror(errno));
        close(exe_fd);
        return 1;
    }

    void *output = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, exe_fd, 0);
    if (output == MAP_FAILED)
    {
        fprintf(stderr, "Packed runtime: mmap failed: %s\n", strerror(errno));
        close(exe_fd);
        return 1;
    }

    wwXzDecoderInit();
    ww_xz_result_t decoded      = wwXzDecode(waterwallPackedBytes, waterwallPackedLength, output, length, length);
    int            unmap_status = munmap(output, length);
    if (decoded != WW_XZ_OK)
    {
        fprintf(stderr, "Packed runtime: restoration failed (%d)\n", (int) decoded);
        close(exe_fd);
        return 1;
    }
    if (unmap_status != 0)
    {
        fprintf(stderr, "Packed runtime: munmap failed: %s\n", strerror(errno));
        close(exe_fd);
        return 1;
    }

    if (fcntl(exe_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0)
    {
        fprintf(stderr, "Packed runtime: sealing failed: %s\n", strerror(errno));
        close(exe_fd);
        return 1;
    }

    /* Format internal handoff arguments */
    char  arg_fd[64];
    char  arg_len[64];
    char *arg_src = NULL;
    char *arg_exe = NULL;
    snprintf(arg_fd, sizeof(arg_fd), "--ww-internal-fd=%d", input_fd);
    snprintf(arg_len, sizeof(arg_len), "--ww-internal-len=%zu", input_len);
    if (asprintf(&arg_src, "--ww-internal-src=%s", input_src) < 0)
    {
        fprintf(stderr, "Packed runtime: cannot allocate source argument\n");
        close(exe_fd);
        return 1;
    }
    if (asprintf(&arg_exe, "--ww-internal-exe=%s", orig_exe) < 0)
    {
        fprintf(stderr, "Packed runtime: cannot allocate executable argument\n");
        free(arg_src);
        close(exe_fd);
        return 1;
    }

    char **new_argv = malloc(((size_t) argc + 5) * sizeof(char *));
    if (new_argv == NULL)
    {
        fprintf(stderr, "Packed runtime: out of memory allocating argv\n");
        free(arg_src);
        free(arg_exe);
        close(exe_fd);
        return 1;
    }

    new_argv[0] = argv[0];
    new_argv[1] = arg_fd;
    new_argv[2] = arg_len;
    new_argv[3] = arg_src;
    new_argv[4] = arg_exe;
    for (int i = 1; i < argc; ++i)
    {
        new_argv[4 + i] = argv[i];
    }
    new_argv[argc + 4] = NULL;

    fflush(stdout);
    fflush(stderr);

    /* Only the snapshot survives execution. Failure leaves it launcher-owned. */
    int flags = fcntl(input_fd, F_GETFD);
    if (flags < 0 || fcntl(input_fd, F_SETFD, flags & ~FD_CLOEXEC) != 0)
    {
        fprintf(stderr, "Packed runtime: input inheritance failed: %s\n", strerror(errno));
    }
    else
    {
        syscall(SYS_execveat, exe_fd, "", new_argv, environ, AT_EMPTY_PATH);
        const int exec_error = errno;
        (void) fcntl(input_fd, F_SETFD, flags);
        fprintf(stderr, "Packed runtime: execveat failed: %s\n", strerror(exec_error));
    }
    free(new_argv);
    free(arg_src);
    free(arg_exe);
    close(exe_fd);
    return 1;
}

int launcherExecute(char *input, size_t length, const char *source, int argc, char *const argv[],
                    const waterwall_startup_options_t *options)
{
    (void) options;
    int input_fd = launcherLinuxCreateSealedInputSnapshot(input, length);
    free(input);
    if (input_fd < 0)
    {
        fprintf(stderr, "Packed runtime: failed to create input snapshot: %s\n", strerror(errno));
        return 1;
    }
    char original_executable[PATH_MAX];
    if (launcherLinuxCaptureExecutablePath(original_executable, sizeof(original_executable)) != 0)
    {
        fprintf(stderr, "Packed runtime: cannot resolve executable location\n");
        close(input_fd);
        return 1;
    }
    int status = launcherLinuxRestoreAndExec(input_fd, length, source, original_executable, argc, argv);
    close(input_fd);
    return status;
}
