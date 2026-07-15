#include "wfrand.h"
#include "wlibc.h"

#include "global_state.h"

#if defined(OS_LINUX)
#include <errno.h>
#include <sys/syscall.h>

#if defined(SYS_getrandom)
#define WFRAND_SYS_GETRANDOM SYS_getrandom
#elif defined(__NR_getrandom)
#define WFRAND_SYS_GETRANDOM __NR_getrandom
#endif
#endif

#if defined(OS_WIN)
#include <limits.h>
#endif

#if defined(OS_UNIX)
#include <errno.h>
#include <unistd.h>
#endif

#if defined(OS_DARWIN) || defined(OS_BSD)
#include <stdlib.h>
#endif

thread_local uint32_t frand_seed32      = 0;
thread_local uint64_t frand_seed64      = 0;

#if defined(OS_LINUX) && defined(WFRAND_SYS_GETRANDOM)
static bool secureRandomBytesGetrandom(uint8_t *dest, size_t len)
{
    size_t offset = 0;
    while (offset < len)
    {
        ssize_t nread = (ssize_t) syscall(WFRAND_SYS_GETRANDOM, dest + offset, len - offset, 0);
        if (UNLIKELY(nread < 0))
        {
            if (UNLIKELY(errno == EINTR))
            {
                continue;
            }
            break;
        }
        if (UNLIKELY(nread == 0))
        {
            break;
        }
        offset += (size_t) nread;
    }
    return offset == len;
}
#endif

#if defined(OS_WIN)
static bool secureRandomBytesWindows(uint8_t *dest, size_t len)
{
    enum
    {
        kBcryptUseSystemPreferredRng = 0x00000002UL
    };
    secure_random_windows_generator_fn gen_random = GSTATE.secure_random.generator;
    if (UNLIKELY(gen_random == NULL))
    {
        return false;
    }

    size_t offset = 0;
    while (offset < len)
    {
        const size_t remaining = len - offset;
        const ULONG  chunk     = remaining > (size_t) ULONG_MAX ? ULONG_MAX : (ULONG) remaining;

        if (UNLIKELY(gen_random(NULL, dest + offset, chunk, kBcryptUseSystemPreferredRng) < 0))
        {
            return false;
        }
        offset += chunk;
    }

    return true;
}
#endif

#if defined(OS_UNIX) && ! (defined(OS_DARWIN) || defined(OS_BSD))
static bool secureRandomBytesUrandom(uint8_t *dest, size_t len)
{
    int fd = GSTATE.secure_random.device_fd;
    if (UNLIKELY(fd < 0))
    {
        return false;
    }

    size_t offset = 0;
    while (offset < len)
    {
        ssize_t nread = read(fd, dest + offset, len - offset);
        if (UNLIKELY(nread < 0))
        {
            if (UNLIKELY(errno == EINTR))
            {
                continue;
            }
            break;
        }
        if (UNLIKELY(nread == 0))
        {
            break;
        }
        offset += (size_t) nread;
    }

    return offset == len;
}
#endif

bool secureRandomBytes(void *bytes, size_t size)
{
    if (size == 0)
    {
        return true;
    }
    if (UNLIKELY(bytes == NULL))
    {
        return false;
    }
    if (UNLIKELY(! GSTATE.secure_random.initialized))
    {
        return false;
    }

    uint8_t *dest = bytes;

#if defined(OS_LINUX) && defined(WFRAND_SYS_GETRANDOM)
    if (LIKELY(secureRandomBytesGetrandom(dest, size)))
    {
        return true;
    }
#endif

#if defined(OS_DARWIN) || defined(OS_BSD)
    arc4random_buf(dest, size);
    return true;
#elif defined(OS_WIN)
    return secureRandomBytesWindows(dest, size);
#elif defined(OS_UNIX)
    return secureRandomBytesUrandom(dest, size);
#else
    discard dest;
    discard size;
    return false;
#endif
}
