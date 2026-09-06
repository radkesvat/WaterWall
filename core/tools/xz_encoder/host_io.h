#ifndef WATERWALL_HOST_IO_H
#define WATERWALL_HOST_IO_H

#include <stdio.h>

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

#endif
