#include "global_state.h"

#if defined(OS_LINUX)
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(SYS_getrandom)
#define WFRAND_TEST_SYS_GETRANDOM SYS_getrandom
#elif defined(__NR_getrandom)
#define WFRAND_TEST_SYS_GETRANDOM __NR_getrandom
#endif

static bool deny_urandom_open;

int __real_open(const char *path, int flags, ...);
int __wrap_open(const char *path, int flags, ...);

int __wrap_open(const char *path, int flags, ...)
{
    if (deny_urandom_open && strcmp(path, "/dev/urandom") == 0)
    {
        errno = ENOENT;
        return -1;
    }

    bool needs_mode = (flags & O_CREAT) != 0;
#if defined(O_TMPFILE)
    needs_mode = needs_mode || (flags & O_TMPFILE) == O_TMPFILE;
#endif
    if (! needs_mode)
    {
        return __real_open(path, flags);
    }

    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    return __real_open(path, flags, mode);
}

static bool linuxGetrandomAvailable(void)
{
#if defined(WFRAND_TEST_SYS_GETRANDOM)
    uint8_t probe = 0;
    ssize_t result;
    do
    {
        result = syscall(WFRAND_TEST_SYS_GETRANDOM, &probe, sizeof(probe), 0);
    } while (result < 0 && errno == EINTR);
    memoryZero(&probe, sizeof(probe));
    return result == 1;
#else
    return false;
#endif
}
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

int main(void)
{
    uint8_t first[66];
    uint8_t second[64];

    memset(first, 0xA5, sizeof(first));
    memset(second, 0xA5, sizeof(second));

    require(secureRandomBytes(NULL, 0), "zero-sized secure random request failed");
    require(! secureRandomBytes(NULL, 1), "secure random accepted a NULL destination");
    require(! secureRandomBytes(second, sizeof(second)), "secure random worked before global initialization");
#if defined(OS_LINUX)
    const bool getrandom_available = linuxGetrandomAvailable();
    deny_urandom_open              = getrandom_available;
#endif
    require(globalstateInitializeSecureRandom(), "secure random global-state initialization failed");
#if defined(OS_LINUX)
    if (getrandom_available)
    {
        require(GSTATE.secure_random.device_fd < 0, "secure random required /dev/urandom despite getrandom support");
    }
    deny_urandom_open = false;
#endif
    require(secureRandomBytes(first + 1, sizeof(first) - 2U), "first secure random request failed");
    require(secureRandomBytes(second, sizeof(second)), "second secure random request failed");
    require(first[0] == 0xA5 && first[sizeof(first) - 1U] == 0xA5, "secure random wrote outside its buffer");
    require(memcmp(first + 1, second, sizeof(second)) != 0, "independent secure random outputs matched");
    globalstateDestroySecureRandom();
    require(! secureRandomBytes(second, sizeof(second)), "secure random worked after global teardown");

    return 0;
}
