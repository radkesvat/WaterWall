#include "os_helpers.h"

#include "loggers/core_logger.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char test_dir[] = "/tmp/waterwall-bbr-test-XXXXXX";
static char log_path[PATH_MAX];
static char state_path[PATH_MAX];

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void writeFakeSysctl(void)
{
    char script_path[PATH_MAX];
    require(snprintf(script_path, sizeof(script_path), "%s/sysctl", test_dir) > 0, "could not build script path");

    FILE *script = fopen(script_path, "w");
    require(script != NULL, "could not create fake sysctl");
    fputs("#!/bin/sh\n"
          "printf '%s\\n' \"$*\" >> \"$WW_BBR_TEST_LOG\"\n"
          "case \"$*\" in\n"
          "  \"-n net.ipv4.tcp_congestion_control\")\n"
          "    if [ \"$WW_BBR_TEST_INITIAL_BBR\" = 1 ] || [ -f \"$WW_BBR_TEST_STATE/bbr-enabled\" ]; then\n"
          "      echo bbr\n"
          "    else\n"
          "      echo cubic\n"
          "    fi\n"
          "    ;;\n"
          "  \"-n net.core.default_qdisc\")\n"
          "    if [ \"$WW_BBR_TEST_INITIAL_FQ\" = 1 ] || [ -f \"$WW_BBR_TEST_STATE/fq-enabled\" ]; then\n"
          "      echo fq\n"
          "    else\n"
          "      echo fq_codel\n"
          "    fi\n"
          "    ;;\n"
          "  \"-w net.core.default_qdisc=fq\")\n"
          "    if [ \"$WW_BBR_TEST_FAIL_FQ\" = 1 ]; then\n"
          "      echo 'sysctl: permission denied on key net.core.default_qdisc' >&2\n"
          "      exit 1\n"
          "    fi\n"
          "    touch \"$WW_BBR_TEST_STATE/fq-enabled\"\n"
          "    echo 'net.core.default_qdisc = fq'\n"
          "    ;;\n"
          "  \"-w net.ipv4.tcp_congestion_control=bbr\")\n"
          "    if [ \"$WW_BBR_TEST_FAIL_BBR\" = 1 ]; then\n"
          "      echo 'sysctl: permission denied on key net.ipv4.tcp_congestion_control' >&2\n"
          "      exit 1\n"
          "    fi\n"
          "    touch \"$WW_BBR_TEST_STATE/bbr-enabled\"\n"
          "    echo 'net.ipv4.tcp_congestion_control = bbr'\n"
          "    ;;\n"
          "  *)\n"
          "    echo \"unexpected sysctl arguments: $*\" >&2\n"
          "    exit 64\n"
          "    ;;\n"
          "esac\n",
          script);
    require(fclose(script) == 0, "could not close fake sysctl");
    require(chmod(script_path, 0700) == 0, "could not make fake sysctl executable");
}

static void resetScenario(void)
{
    unlink(log_path);

    char marker_path[PATH_MAX];
    snprintf(marker_path, sizeof(marker_path), "%s/bbr-enabled", state_path);
    unlink(marker_path);
    snprintf(marker_path, sizeof(marker_path), "%s/fq-enabled", state_path);
    unlink(marker_path);

    unsetenv("WW_BBR_TEST_INITIAL_BBR");
    unsetenv("WW_BBR_TEST_INITIAL_FQ");
    unsetenv("WW_BBR_TEST_FAIL_FQ");
    unsetenv("WW_BBR_TEST_FAIL_BBR");
}

static void readCommandLog(char *output, size_t output_size)
{
    FILE *log = fopen(log_path, "r");
    require(log != NULL, "fake sysctl command log was not created");
    size_t size = fread(output, 1, output_size - 1U, log);
    require(! ferror(log), "could not read fake sysctl command log");
    output[size] = '\0';
    fclose(log);
}

static void testUnregisteredBbrIsAttempted(void)
{
    resetScenario();
    setenv("WW_BBR_TEST_INITIAL_FQ", "1", 1);

    tryEnableBbr();

    char commands[4096];
    readCommandLog(commands, sizeof(commands));
    require(strstr(commands, "-w net.ipv4.tcp_congestion_control=bbr\n") != NULL,
            "BBR was not attempted when it was initially unregistered");
    require(strstr(commands, "tcp_available_congestion_control") == NULL,
            "registered-only congestion-control precheck was used");
}

static void testAlreadyEnabledBbrStillConfiguresFq(void)
{
    resetScenario();
    setenv("WW_BBR_TEST_INITIAL_BBR", "1", 1);

    tryEnableBbr();

    char commands[4096];
    readCommandLog(commands, sizeof(commands));
    require(strstr(commands, "-w net.core.default_qdisc=fq\n") != NULL,
            "fq was not configured when BBR was already enabled");
    require(strstr(commands, "-w net.ipv4.tcp_congestion_control=bbr\n") == NULL,
            "BBR was rewritten even though it was already enabled");
}

static void testQdiscFailureDoesNotBlockBbrAttempt(void)
{
    resetScenario();
    setenv("WW_BBR_TEST_FAIL_FQ", "1", 1);

    tryEnableBbr();

    char commands[4096];
    readCommandLog(commands, sizeof(commands));
    require(strstr(commands, "-w net.core.default_qdisc=fq\n") != NULL, "fq failure scenario did not attempt fq");
    require(strstr(commands, "-w net.ipv4.tcp_congestion_control=bbr\n") != NULL,
            "fq failure prevented the BBR attempt");
}

static void testBbrFailureDoesNotChangeQdisc(void)
{
    resetScenario();
    setenv("WW_BBR_TEST_FAIL_BBR", "1", 1);

    tryEnableBbr();

    char commands[4096];
    readCommandLog(commands, sizeof(commands));
    require(strstr(commands, "-w net.ipv4.tcp_congestion_control=bbr\n") != NULL,
            "BBR failure scenario did not attempt BBR");
    require(strstr(commands, "net.core.default_qdisc") == NULL,
            "default qdisc was changed even though BBR could not be enabled");
}

int main(void)
{
    require(mkdtemp(test_dir) != NULL, "could not create temporary test directory");
    require(snprintf(log_path, sizeof(log_path), "%s/commands.log", test_dir) > 0, "could not build log path");
    require(snprintf(state_path, sizeof(state_path), "%s/state", test_dir) > 0, "could not build state path");
    require(mkdir(state_path, 0700) == 0, "could not create fake sysctl state directory");

    writeFakeSysctl();
    setenv("WW_BBR_TEST_LOG", log_path, 1);
    setenv("WW_BBR_TEST_STATE", state_path, 1);

    const char *original_path = getenv("PATH");
    require(original_path != NULL, "PATH is not set");
    char *saved_path = strdup(original_path);
    require(saved_path != NULL, "could not save PATH");

    char test_path[PATH_MAX * 2U];
    require(snprintf(test_path, sizeof(test_path), "%s:%s", test_dir, saved_path) > 0, "could not build test PATH");
    setenv("PATH", test_path, 1);

    createCoreLogger(NULL, true);
    testUnregisteredBbrIsAttempted();
    testAlreadyEnabledBbrStillConfiguresFq();
    testQdiscFailureDoesNotBlockBbrAttempt();
    testBbrFailureDoesNotChangeQdisc();
    coreloggerDestroy();

    setenv("PATH", saved_path, 1);
    free(saved_path);
    resetScenario();

    char cleanup_path[PATH_MAX];
    snprintf(cleanup_path, sizeof(cleanup_path), "%s/sysctl", test_dir);
    unlink(cleanup_path);
    rmdir(state_path);
    rmdir(test_dir);
    return 0;
}
