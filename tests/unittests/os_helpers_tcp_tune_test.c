#include "loggers/core_logger.h"
#include "os_helpers.h"
#include <sys/stat.h>
#include <unistd.h>

static char     test_dir[] = "/tmp/waterwall-tcp-tune-test-XXXXXX";
static char     log_path[PATH_MAX];
static unsigned warnings;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void captureLog(int level, const char *message, int length)
{
    if (level == LOG_LEVEL_WARN)
        ++warnings;
    discard message;
    discard length;
}

static void createFakeSysctl(void)
{
    require(mkdtemp(test_dir) != NULL, "could not create TCP tuning fixture directory");
    snprintf(log_path, sizeof(log_path), "%s/commands.log", test_dir);
    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir);
    FILE *script = fopen(script_path, "w");
    require(script != NULL, "could not create fake sysctl");
    fputs("#!/bin/sh\n"
          "[ \"$#\" = 2 ] && [ \"$1\" = '-w' ] || exit 64\n"
          "printf '%s\\n' \"$2\" >> \"$WW_TCP_TUNE_TEST_LOG\"\n"
          "case \"$2\" in\n"
          "  \"$WW_TCP_TUNE_TEST_FAIL_KEY\"=*) echo 'permission denied' >&2; exit 1;;\n"
          "esac\n",
          script);
    require(fclose(script) == 0 && chmod(script_path, 0700) == 0, "could not prepare fake sysctl");
    /* Shell builtins only; the real host sysctl is never reachable. */
    require(setenv("PATH", test_dir, 1) == 0 && setenv("WW_TCP_TUNE_TEST_LOG", log_path, 1) == 0,
            "could not install isolated sysctl fixture");
}

static void testProfile(unsigned int profile, unsigned int buffer_max, unsigned int backlog, unsigned int somaxconn,
                        const char *fail_key)
{
    unlink(log_path);
    warnings = 0;
    require(setenv("WW_TCP_TUNE_TEST_FAIL_KEY", fail_key, 1) == 0, "could not select failing setting");
    tryTuneTcp(profile);

    FILE *log = fopen(log_path, "r");
    require(log != NULL, "TCP tuning did not invoke sysctl");
    char         commands[1024] = {0};
    const size_t length         = fread(commands, 1, sizeof(commands) - 1, log);
    require(! ferror(log) && length < sizeof(commands) - 1, "could not read complete command log");
    fclose(log);
    char expected[1024];
    snprintf(expected,
             sizeof(expected),
             "net.core.rmem_max=%u\nnet.core.wmem_max=%u\n"
             "net.ipv4.tcp_rmem=4096 87380 %u\nnet.ipv4.tcp_wmem=4096 65536 %u\n"
             "net.core.netdev_max_backlog=%u\nnet.core.somaxconn=%u\n",
             buffer_max,
             buffer_max,
             buffer_max,
             buffer_max,
             backlog,
             somaxconn);
    require(strcmp(commands, expected) == 0, "incorrect tuning values, argument quoting or continuation after failure");
    require(warnings == (fail_key[0] == '\0' ? 0U : 1U), "failed tuning did not log exactly one warning");
}

int main(void)
{
    createFakeSysctl();
    logger_t *logger = createCoreLogger(NULL, false);
    require(logger != NULL, "failed to create core logger");
    loggerSetHandler(logger, captureLog);

    testProfile(kRamProfileS1Memory, 134217728U, 8000U, 65535U, "");
    testProfile(kRamProfileS2Memory, 134217728U, 8000U, 65535U, "");
    testProfile(kRamProfileM1Memory, 268435456U, 16000U, 131071U, "");
    testProfile(kRamProfileM2Memory, 268435456U, 16000U, 131071U, "");
    testProfile(kRamProfileL1Memory, 536870912U, 32000U, 262143U, "");
    testProfile(kRamProfileL2Memory, 536870912U, 32000U, 262143U, "");
    const char *keys[] = {"net.core.rmem_max",
                          "net.core.wmem_max",
                          "net.ipv4.tcp_rmem",
                          "net.ipv4.tcp_wmem",
                          "net.core.netdev_max_backlog",
                          "net.core.somaxconn"};
    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
        testProfile(kRamProfileS2Memory, 134217728U, 8000U, 65535U, keys[i]);

    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir);
    require(unlink(script_path) == 0, "could not remove fake sysctl");
    unlink(log_path);
    warnings = 0;
    tryTuneTcp(kRamProfileS2Memory);
    require(warnings == 6 && access(log_path, F_OK) != 0, "missing sysctl was not a nonfatal best-effort failure");
    coreloggerDestroy();
    rmdir(test_dir);
    return 0;
}
