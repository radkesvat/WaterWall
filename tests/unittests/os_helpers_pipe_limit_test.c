#include "loggers/core_logger.h"
#include "os_helpers.h"
#include <sys/stat.h>
#include <unistd.h>

static char test_dir[] = "/tmp/waterwall-pipe-limit-test-XXXXXX";
static char log_path[PATH_MAX];
static long test_page_size;

long __real_sysconf(int name);
long __wrap_sysconf(int name);
long __wrap_sysconf(int name)
{
    return name == _SC_PAGESIZE ? test_page_size : __real_sysconf(name);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void createFakeSysctl(void)
{
    require(mkdtemp(test_dir) != NULL, "could not create the pipe-limit fixture directory");
    snprintf(log_path, sizeof(log_path), "%s/commands.log", test_dir);
    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir);
    FILE *script = fopen(script_path, "w");
    require(script != NULL, "could not create fake sysctl");
    fputs("#!/bin/sh\n"
          "printf '%s\\n' \"$*\" >> \"$WW_PIPE_LIMIT_TEST_LOG\"\n"
          "case \"$*\" in\n"
          "  '-n fs.pipe-user-pages-soft fs.pipe-user-pages-hard')\n"
          "    printf '%s' \"$WW_PIPE_LIMIT_TEST_OUTPUT\"\n"
          "    exit \"$WW_PIPE_LIMIT_TEST_READ_EXIT\";;\n"
          "  '-w fs.pipe-user-pages-soft='*)\n"
          "    exit \"$WW_PIPE_LIMIT_TEST_WRITE_EXIT\";;\n"
          "  *) exit 64;;\n"
          "esac\n",
          script);
    require(fclose(script) == 0 && chmod(script_path, 0700) == 0, "could not prepare fake sysctl");
    // This fixture needs only shell builtins; no fallback to the host's real sysctl.
    require(setenv("PATH", test_dir, 1) == 0 && setenv("WW_PIPE_LIMIT_TEST_LOG", log_path, 1) == 0,
            "could not install the isolated sysctl fixture");
}

int main(void)
{
    createFakeSysctl();
    createCoreLogger(NULL, true);
#if WW_HAVE_SPLICE
    const struct
    {
        const char   *output;
        int           read_status, write_status;
        long          page_size;
        unsigned long expected_target;
    } cases[] = {
        {"16384\n32768\n", 0, 0, -1, 32768},
        {"16384\n32768\n", 0, 1, 4096, 32768},
        {"16384\n0\n", 0, 0, 4096, 131072},
        {"16384\n0\n", 0, 1, 4096, 131072},
        {"131071\n0\n", 0, 0, 4096, 131072},
        {"131072\n0\n", 0, 0, 4096, 0},
        {"262144\n0\n", 0, 0, 4096, 0},
        {"1024\n0\n", 0, 0, 65536, 8192},
        {"8192\n0\n", 0, 0, 65536, 0},
        {"16384\n0\n", 0, 0, 65536, 0},
        {"16384\n0\n", 0, 0, -1, 0},
        {"16384\n0\n", 0, 0, 0, 0},
        {"0\n32768\n", 0, 0, 4096, 0},
        {"0\n0\n", 0, 0, 4096, 0},
        {"32768\n32768\n", 0, 0, 4096, 0},
        {"65536\n32768\n", 0, 0, 4096, 0},
        {"sysctl unavailable", 127, 0, 4096, 0},
        {"16384\nmissing hard limit", 1, 0, 4096, 0},
        {"", 0, 0, 4096, 0},
        {"16384\n", 0, 0, 4096, 0},
        {"-1\n32768\n", 0, 0, 4096, 0},
        {"16384\n-1\n", 0, 0, 4096, 0},
        {"16384\n32768x\n", 0, 0, 4096, 0},
        {"16384\n32768\nextra\n", 0, 0, 4096, 0},
        {"16384\n18446744073709551616\n", 0, 0, 4096, 0},
        {" 16384\t\n 32768 \n", 0, 0, 4096, 32768},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        unlink(log_path);
        test_page_size = cases[i].page_size;
        char read_exit[16], write_exit[16];
        snprintf(read_exit, sizeof(read_exit), "%d", cases[i].read_status);
        snprintf(write_exit, sizeof(write_exit), "%d", cases[i].write_status);
        require(setenv("WW_PIPE_LIMIT_TEST_OUTPUT", cases[i].output, 1) == 0 &&
                    setenv("WW_PIPE_LIMIT_TEST_READ_EXIT", read_exit, 1) == 0 &&
                    setenv("WW_PIPE_LIMIT_TEST_WRITE_EXIT", write_exit, 1) == 0,
                "could not configure pipe-limit scenario");
        tryIncreasePipeLimit();
        FILE *log = fopen(log_path, "r");
        require(log != NULL, "startup did not invoke fake sysctl");
        char   commands[512] = {0};
        size_t length        = fread(commands, 1, sizeof(commands) - 1, log);
        require(! ferror(log) && length < sizeof(commands) - 1, "could not read complete sysctl command log");
        fclose(log);
        char expected[512] = "-n fs.pipe-user-pages-soft fs.pipe-user-pages-hard\n";
        if (cases[i].expected_target != 0)
        {
            const size_t offset = strlen(expected);
            snprintf(expected + offset,
                     sizeof(expected) - offset,
                     "-w fs.pipe-user-pages-soft=%lu\n",
                     cases[i].expected_target);
        }
        require(strcmp(commands, expected) == 0, "startup attempted an incorrect pipe-limit operation or retried");
    }
#else
    tryIncreasePipeLimit();
    require(access(log_path, F_OK) != 0, "unsupported splice build changed system pipe limits");
#endif
    coreloggerDestroy();
    unlink(log_path);
    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir);
    unlink(script_path);
    rmdir(test_dir);
    return 0;
}
