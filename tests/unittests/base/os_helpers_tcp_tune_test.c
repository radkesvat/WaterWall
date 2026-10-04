/*
 * Covers: os helpers tcp tune; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testProfile
 * Checks: Assertion labels include: TCP tuning did not invoke sysctl; incorrect tuning values, argument
 * quoting or continuation after failure; failed tuning did not log exactly one warning; missing sysctl
 * was not a nonfatal best-effort failure
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.os_helpers_tcp_tune_unit
 */
#include "loggers/core_logger.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "global_state.h"
#include "os_helpers.h"
#include <sys/stat.h>
#include <unistd.h>

static char     test_dir[] = "/tmp/waterwall-tcp-tune-test-XXXXXX";
static char     log_path[PATH_MAX];
static unsigned warnings;


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

static void testProfile(unsigned int profile, const char *fail_key)
{
    unlink(log_path);
    warnings = 0;
    require(setenv("WW_TCP_TUNE_TEST_FAIL_KEY", fail_key, 1) == 0, "could not select failing setting");
    GSTATE.ram_profile = profile;
    tryTuneTcp();

    FILE *log = fopen(log_path, "r");
    require(log != NULL, "TCP tuning did not invoke sysctl");
    char         commands[1024] = {0};
    const size_t length         = fread(commands, 1, sizeof(commands) - 1, log);
    require(! ferror(log) && length < sizeof(commands) - 1, "could not read complete command log");
    fclose(log);
    const char *expected = "net.core.rmem_max=534217728\nnet.core.wmem_max=534217728\n"
                           "net.ipv4.tcp_rmem=4096 87380 134217728\nnet.ipv4.tcp_wmem=4096 87380 134217728\n";
    require(strcmp(commands, expected) == 0, "incorrect tuning values, argument quoting or continuation after failure");
    require(warnings == (fail_key[0] == '\0' ? 0U : 1U), "failed tuning did not log exactly one warning");
}

int main(void)
{
    testCaseSet("os_helpers_tcp_tune_test");
    createFakeSysctl();
    logger_t *logger = createCoreLogger(NULL, false);
    require(logger != NULL, "failed to create core logger");
    loggerSetHandler(logger, captureLog);

    testProfile(kRamProfileS1Memory, "");
    testProfile(kRamProfileS2Memory, "");
    testProfile(kRamProfileM1Memory, "");
    testProfile(kRamProfileM2Memory, "");
    testProfile(kRamProfileL1Memory, "");
    testProfile(kRamProfileL2Memory, "");
    const char *keys[] = {"net.core.rmem_max", "net.core.wmem_max", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem"};
    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
        testProfile(kRamProfileS2Memory, keys[i]);

    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir);
    require(unlink(script_path) == 0, "could not remove fake sysctl");
    unlink(log_path);
    warnings = 0;
    tryTuneTcp();
    require(warnings == 4 && access(log_path, F_OK) != 0, "missing sysctl was not a nonfatal best-effort failure");
    coreloggerDestroy();
    rmdir(test_dir);
    return 0;
}
