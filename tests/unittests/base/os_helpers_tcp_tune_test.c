/*
 * Covers: native Linux best-effort startup TCP tuning through an isolated sysctl fixture.
 * Cases: fixed socket targets across RAM profiles; tcp_mem host RAM/page conversion, exact
 * 3:4:6 rounding, no lowering, invalid/overflow inputs, memory failures, denied writes,
 * failed verification, and mismatched readback; disabled splice skips tcp_mem entirely.
 * All failures preserve the other four attempts.
 * Setup: shell builtins only with PATH restricted to a temporary fixture; linker-wrapped
 * sysinfo/sysconf provide deterministic host RAM and page sizes. No host sysctl is reachable.
 * Limits: Does not establish throughput improvement or real kernel permission behavior.
 * CTest: waterwall.os_helpers_tcp_tune_unit
 */
#include "loggers/core_logger.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "global_state.h"
#include "os_helpers.h"
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>

static char          test_dir[] = "/tmp/waterwall-tcp-tune-test-XXXXXX";
static char          log_path[PATH_MAX];
static char          state_path[PATH_MAX];
static char          last_warning[2048];
static unsigned      warnings;
static bool          verified_success;
static unsigned long test_totalram;
static unsigned int  test_mem_unit;
static int           test_sysinfo_status;
static long          test_page_size;

static const char *initial_limits = "786432 1048576 1572864";
static const char *fixed_commands = "-w net.core.rmem_max=134217728\n-w net.core.wmem_max=134217728\n"
                                    "-w net.ipv4.tcp_rmem=4096 87380 134217728\n"
                                    "-w net.ipv4.tcp_wmem=4096 87380 134217728\n";

int __wrap_sysinfo(struct sysinfo *info);
int __wrap_sysinfo(struct sysinfo *info)
{
    memset(info, 0, sizeof(*info));
    info->totalram = test_totalram;
    info->mem_unit = test_mem_unit;
    errno          = EIO;
    return test_sysinfo_status;
}

long __real_sysconf(int name);
long __wrap_sysconf(int name);
long __wrap_sysconf(int name)
{
    return name == _SC_PAGESIZE ? test_page_size : __real_sysconf(name);
}

static void captureLog(int level, const char *message, int length)
{
    if (level == LOG_LEVEL_WARN)
    {
        ++warnings;
        snprintf(last_warning, sizeof(last_warning), "%.*s", length, message);
    }
    if (strstr(message, "TCP memory limits raised from") != NULL)
    {
        verified_success = true;
    }
}

static void createFakeSysctl(void)
{
    require(mkdtemp(test_dir) != NULL, "could not create TCP tuning fixture directory");
    snprintf(log_path, sizeof(log_path), "%s/commands.log", test_dir);
    snprintf(state_path, sizeof(state_path), "%s/memory-written", test_dir);
    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir);
    FILE *script = fopen(script_path, "w");
    require(script != NULL, "could not create fake sysctl");
    fputs("#!/bin/sh\n"
          "[ \"$#\" = 2 ] || exit 64\n"
          "printf '%s\\n' \"$*\" >> \"$WW_TCP_TUNE_TEST_LOG\"\n"
          "case \"$*\" in\n"
          "  '-n net.ipv4.tcp_mem')\n"
          "    if [ -f \"$WW_TCP_TUNE_TEST_STATE\" ]; then\n"
          "      printf '%s' \"$WW_TCP_TUNE_TEST_CONFIRMED\"\n"
          "      exit \"$WW_TCP_TUNE_TEST_VERIFY_EXIT\"\n"
          "    fi\n"
          "    printf '%s' \"$WW_TCP_TUNE_TEST_INITIAL\"\n"
          "    exit \"$WW_TCP_TUNE_TEST_READ_EXIT\";;\n"
          "  '-w net.ipv4.tcp_mem='*)\n"
          "    if [ \"$WW_TCP_TUNE_TEST_WRITE_EXIT\" != 0 ]; then\n"
          "      echo 'permission denied' >&2\n"
          "      exit \"$WW_TCP_TUNE_TEST_WRITE_EXIT\"\n"
          "    fi\n"
          "    : > \"$WW_TCP_TUNE_TEST_STATE\";;\n"
          "  '-w '*)\n"
          "    case \"$2\" in\n"
          "      \"$WW_TCP_TUNE_TEST_FAIL_KEY\"=*) echo 'permission denied' >&2; exit 1;;\n"
          "    esac;;\n"
          "  *) exit 64;;\n"
          "esac\n",
          script);
    require(fclose(script) == 0 && chmod(script_path, 0700) == 0, "could not prepare fake sysctl");
    /* Shell builtins only; the real host sysctl is never reachable. */
    require(setenv("PATH", test_dir, 1) == 0 && setenv("WW_TCP_TUNE_TEST_LOG", log_path, 1) == 0 &&
                setenv("WW_TCP_TUNE_TEST_STATE", state_path, 1) == 0,
            "could not install isolated sysctl fixture");
}

static void selectSetting(const char *key, const char *value)
{
    require(setenv(key, value, 1) == 0, "could not configure TCP tuning scenario");
}

static void resetScenario(void)
{
    unlink(log_path);
    unlink(state_path);
    warnings            = 0;
    verified_success    = false;
    last_warning[0]     = '\0';
    test_totalram       = 16UL * 1024UL * 1024UL;
    test_mem_unit       = 1024;
    test_sysinfo_status = 0;
    test_page_size      = 4096;
    selectSetting("WW_TCP_TUNE_TEST_INITIAL", initial_limits);
    selectSetting("WW_TCP_TUNE_TEST_CONFIRMED", initial_limits);
    selectSetting("WW_TCP_TUNE_TEST_READ_EXIT", "0");
    selectSetting("WW_TCP_TUNE_TEST_WRITE_EXIT", "0");
    selectSetting("WW_TCP_TUNE_TEST_VERIFY_EXIT", "0");
    selectSetting("WW_TCP_TUNE_TEST_FAIL_KEY", "");
}

static void checkCommands(const char *target, bool verify)
{
    FILE *log = fopen(log_path, "r");
    require(log != NULL, "TCP tuning did not invoke sysctl");
    char         commands[1024] = {0};
    const size_t length         = fread(commands, 1, sizeof(commands) - 1, log);
    require(! ferror(log) && length < sizeof(commands) - 1, "could not read complete command log");
    fclose(log);
    char expected[1024] = "-n net.ipv4.tcp_mem\n";
    if (target != NULL)
    {
        size_t offset = strlen(expected);
        snprintf(expected + offset, sizeof(expected) - offset, "-w net.ipv4.tcp_mem=%s\n", target);
        if (verify)
        {
            offset = strlen(expected);
            snprintf(expected + offset, sizeof(expected) - offset, "-n net.ipv4.tcp_mem\n");
        }
    }
    size_t offset = strlen(expected);
    snprintf(expected + offset, sizeof(expected) - offset, "%s", fixed_commands);
    require(strcmp(commands, expected) == 0, "incorrect tuning values, argument quoting or continuation after failure");
}

static void testProfile(unsigned int profile, const char *fail_key)
{
    resetScenario();
    selectSetting("WW_TCP_TUNE_TEST_FAIL_KEY", fail_key);
    GSTATE.ram_profile = profile;
    tryTuneTcp(true);
    checkCommands(NULL, false);
    require(warnings == (fail_key[0] == '\0' ? 0U : 1U), "failed tuning did not log exactly one warning");
}

static void testMemoryArithmetic(void)
{
    const struct
    {
        const char   *name;
        unsigned long totalram;
        unsigned int  mem_unit;
        long          page_size;
        const char   *target;
        bool          valid;
    } cases[] = {
        {"16 GiB / 4 KiB", 16UL * 1024UL * 1024UL, 1024, 4096, "786432 1048576 1572864", true},
        {"16 GiB / 64 KiB", 16UL * 1024UL * 1024UL, 1024, 65536, "49152 65536 98304", true},
        {"memory unit scaling", 16UL * 1024UL, 1024UL * 1024UL, 4096, "786432 1048576 1572864", true},
        {"round incomplete pages and ratio", 16UL * 4096UL + 4095UL, 1, 4096, "3 4 6", true},
        {"round incomplete ratio unit", 31UL * 4096UL + 4095UL, 1, 4096, "3 4 6", true},
        {"too few pages", 15UL * 4096UL + 4095UL, 1, 4096, NULL, false},
        {"zero host RAM", 0, 1024, 4096, NULL, false},
        {"zero memory unit", 1024, 0, 4096, NULL, false},
        {"page query failure", 1024, 1024, -1, NULL, false},
        {"zero page size", 1024, 1024, 0, NULL, false},
#if ULONG_MAX > UINT32_MAX
        {"host byte multiplication overflow", ULONG_MAX, 2, 4096, NULL, false},
        {"maximum representable host bytes",
         ULONG_MAX,
         1,
         1,
         "3458764513820540925 4611686018427387900 6917529027641081850",
         true},
#else
        {"native signed sysctl overflow", ULONG_MAX, UINT_MAX, 4096, NULL, false},
#endif
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        resetScenario();
        selectSetting("WW_TCP_TUNE_TEST_INITIAL", "0 0 0");
        if (cases[i].target != NULL)
            selectSetting("WW_TCP_TUNE_TEST_CONFIRMED", cases[i].target);
        test_totalram  = cases[i].totalram;
        test_mem_unit  = cases[i].mem_unit;
        test_page_size = cases[i].page_size;
        tryTuneTcp(true);
        checkCommands(cases[i].target, cases[i].valid);
        require(warnings == (cases[i].valid ? 0U : 1U), "RAM arithmetic produced incorrect warnings");
        require(verified_success == cases[i].valid, "RAM arithmetic incorrectly reported verified tuning");
    }
}

static void testExistingLimits(void)
{
    const char *preserve[] = {
        "786432 1048576 1572864",  /* Already the target. */
        "1000000 2000000 3000000", /* All higher. */
        "786433 800000 900000",    /* Only minimum higher. */
        "1 1048577 1200000",       /* Only pressure higher. */
        "1 2 1572865",             /* Only maximum higher. */
    };
    for (size_t i = 0; i < ARRAY_SIZE(preserve); ++i)
    {
        testCaseSet("preserve existing thresholds");
        resetScenario();
        selectSetting("WW_TCP_TUNE_TEST_INITIAL", preserve[i]);
        tryTuneTcp(true);
        checkCommands(NULL, false);
        require(warnings == 0 && ! verified_success, "preserved limits attempted tuning or emitted warnings");
    }
    resetScenario();
    selectSetting("WW_TCP_TUNE_TEST_INITIAL", "786432 1048576 1572863");
    tryTuneTcp(true);
    checkCommands(initial_limits, true);
    require(warnings == 0 && verified_success, "a useful increase with unchanged earlier thresholds was skipped");
}

static void testFailures(void)
{
    const char *invalid[] = {"",
                             "1",
                             "1 2",
                             "-1 2 3",
                             "+1 2 3",
                             "1 -2 3",
                             "1 2 -3",
                             "1 2 3x",
                             "1 2 3 extra",
                             "1 2 3 4",
                             "3 2 1",
                             "1 2 18446744073709551616"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        testCaseSet("malformed initial limits");
        resetScenario();
        selectSetting("WW_TCP_TUNE_TEST_INITIAL", invalid[i]);
        tryTuneTcp(true);
        checkCommands(NULL, false);
        require(warnings == 1 && ! verified_success, "invalid initial limits were not rejected");
    }
    resetScenario();
    char oversized[128];
    snprintf(oversized, sizeof(oversized), "1 2 %lu", (unsigned long) LONG_MAX + 1UL);
    selectSetting("WW_TCP_TUNE_TEST_INITIAL", oversized);
    tryTuneTcp(true);
    checkCommands(NULL, false);
    require(warnings == 1 && ! verified_success, "out-of-range native sysctl threshold was accepted");

    testCaseSet("sysctl read failure");
    resetScenario();
    selectSetting("WW_TCP_TUNE_TEST_READ_EXIT", "1");
    tryTuneTcp(true);
    checkCommands(NULL, false);
    require(warnings == 1 && ! verified_success, "read failure was not nonfatal");

    testCaseSet("host memory query failure");
    resetScenario();
    test_sysinfo_status = -1;
    tryTuneTcp(true);
    checkCommands(NULL, false);
    require(warnings == 1 && ! verified_success, "host memory query failure was not nonfatal");

    testCaseSet("write denial");
    resetScenario();
    selectSetting("WW_TCP_TUNE_TEST_INITIAL", "1 2 3");
    selectSetting("WW_TCP_TUNE_TEST_WRITE_EXIT", "1");
    tryTuneTcp(true);
    checkCommands(initial_limits, false);
    require(warnings == 1 && ! verified_success, "write denial was not nonfatal");

    const char *readbacks[] = {"0 0 0", "1 2", "786432 1048576 1572864"};
    for (size_t i = 0; i < ARRAY_SIZE(readbacks); ++i)
    {
        testCaseSet("readback failure or mismatch");
        resetScenario();
        selectSetting("WW_TCP_TUNE_TEST_INITIAL", "1 2 3");
        selectSetting("WW_TCP_TUNE_TEST_CONFIRMED", readbacks[i]);
        if (i == 2)
            selectSetting("WW_TCP_TUNE_TEST_VERIFY_EXIT", "1");
        tryTuneTcp(true);
        checkCommands(initial_limits, true);
        require(warnings == 1 && ! verified_success, "unverified tuning incorrectly reported success");
        if (i == 0)
            require(strstr(last_warning, "original 1 2 3, confirmed 0 0 0") != NULL,
                    "mismatched readback omitted original and confirmed thresholds");
    }

    testCaseSet("valid whitespace");
    resetScenario();
    selectSetting("WW_TCP_TUNE_TEST_INITIAL", " \t1\n 2 \t3\n");
    tryTuneTcp(true);
    checkCommands(initial_limits, true);
    require(warnings == 0 && verified_success, "valid whitespace-separated limits were rejected");
}

static void testSpliceDisabled(void)
{
    testCaseSet("disabled splice skips TCP memory tuning");
    resetScenario();
    selectSetting("WW_TCP_TUNE_TEST_READ_EXIT", "1");
    tryTuneTcp(false);

    FILE *log = fopen(log_path, "r");
    require(log != NULL, "disabled splice skipped fixed socket tuning");
    char         commands[1024] = {0};
    const size_t length         = fread(commands, 1, sizeof(commands) - 1, log);
    require(! ferror(log) && length < sizeof(commands) - 1, "could not read complete command log");
    fclose(log);
    require(strcmp(commands, fixed_commands) == 0, "disabled splice probed or wrote TCP memory limits");
    require(warnings == 0 && ! verified_success, "disabled splice ran TCP memory tuning");
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
    testMemoryArithmetic();
    testExistingLimits();
    testFailures();
    testSpliceDisabled();

    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir);
    require(unlink(script_path) == 0, "could not remove fake sysctl");
    resetScenario();
    tryTuneTcp(true);
    require(warnings == 5 && access(log_path, F_OK) != 0, "missing sysctl was not a nonfatal best-effort failure");
    coreloggerDestroy();
    rmdir(test_dir);
    return 0;
}
