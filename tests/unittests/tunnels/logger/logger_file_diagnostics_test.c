/* Exercise real LoggerTunnel file output and native fopen/fclose failures.
 * No line callbacks, worker pools, or network traffic are involved.
 * CTest: waterwall.logger_file_diagnostics_unit. */
#include "LoggerTunnel/structure.h"
#include "loggers/network_logger.h"
#include "test_assert.h"

#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static char     diagnostic[8192];
static unsigned diagnostics;

static void captureDiagnostic(int level, const char *message, int length)
{
    require(level == LOG_LEVEL_ERROR, "file failure changed severity");
    require(length > 0 && (size_t) length < sizeof(diagnostic), "diagnostic exceeded capture capacity");
    memoryCopy(diagnostic, message, (size_t) length);
    diagnostic[length] = '\0';
    ++diagnostics;
}

static void submit(tunnel_t *tunnel, sbuf_t *payload, bool upstream)
{
    diagnostics   = 0;
    diagnostic[0] = '\0';
    loggertunnelHandlePayload(tunnel, payload, upstream);
    require(diagnostics == 1, "file failure must produce one diagnostic");
    require(sbufGetLength(payload) == 3, "diagnostic changed payload ownership or length");
}

static void expectFailure(const char *action, const char *escaped_path, int error)
{
    char field[4096];
    snprintf(field, sizeof(field), "path=\"%s\"", escaped_path);
    require(strstr(diagnostic, action) != NULL, "diagnostic omitted the failed operation");
    require(strstr(diagnostic, field) != NULL, "diagnostic omitted the failing output identity");
    snprintf(field, sizeof(field), "errno=%d,", error);
    require(strstr(diagnostic, field) != NULL, "diagnostic lost the native failure code");
    require(strstr(diagnostic, "requested_bytes=3") != NULL, "diagnostic lost requested byte count");
}

int main(void)
{
    testCaseSet("LoggerTunnel file failure diagnostics");
    logger_t *logger = createNetworkLogger(NULL, false);
    require(logger != NULL, "create diagnostic logger");
    loggerSetLevel(logger, LOG_LEVEL_ERROR);
    loggerSetFormat(logger, "%s");
    loggerEnableColor(logger, 0);
    loggerSetHandler(logger, captureDiagnostic);

    char directory[] = "/tmp/waterwall-logger-diagnostics-XXXXXX";
    require(mkdtemp(directory) != NULL, "create isolated temporary directory");
    tunnel_t *tunnel = tunnelCreate(NULL, sizeof(loggertunnel_tstate_t), 0);
    require(tunnel != NULL, "create file-output fixture");
    loggertunnel_tstate_t *state = tunnelGetState(tunnel);
    require(mutexTryInit(&state->file_mutex), "initialize file-output mutex");
    state->mode     = kLoggerTunnelModeFile;
    sbuf_t *payload = sbufCreate(3);
    sbufSetLength(payload, 3);
    sbufWrite(payload, "abc", 3);

    testCaseSet("equal-length output paths remain distinguishable");
    char first[256], second[256];
    snprintf(first, sizeof(first), "%s/missing/first.log", directory);
    snprintf(second, sizeof(second), "%s/missing/other.log", directory);
    require(strlen(first) == strlen(second), "fixture paths must have equal lengths");
    state->output_mode = kLoggerTunnelOutputModeSplitDirection;
    state->up_path     = first;
    state->down_path   = second;
    submit(tunnel, payload, true);
    expectFailure("failed to open output file", first, ENOENT);
    require(strstr(diagnostic, second) == NULL, "upstream failure named the downstream output");
    submit(tunnel, payload, false);
    expectFailure("failed to open output file", second, ENOENT);
    require(strstr(diagnostic, first) == NULL, "downstream failure named the upstream output");

    testCaseSet("per-payload failures retain generated sequence names");
    state->output_mode = kLoggerTunnelOutputModePerPayload;
    state->file_prefix = first;
    for (unsigned sequence = 1; sequence <= 2; ++sequence)
    {
        char generated[288];
        snprintf(generated, sizeof(generated), "%s-up-%u.txt", first, sequence);
        submit(tunnel, payload, true);
        expectFailure("failed to open output file", generated, ENOENT);
    }

    testCaseSet("untrusted path bytes cannot forge a log line");
    char unsafe_path[256], escaped_path[320];
    snprintf(unsafe_path, sizeof(unsafe_path), "%s/missing/bad\n\r\t\"\\\033\177.log", directory);
    snprintf(escaped_path, sizeof(escaped_path), "%s/missing/bad\\x0a\\x0d\\x09\\x22\\x5c\\x1b\\x7f.log", directory);
    state->output_mode = kLoggerTunnelOutputModeSingleFile;
    state->all_path    = unsafe_path;
    submit(tunnel, payload, true);
    expectFailure("failed to open output file", escaped_path, ENOENT);
    const size_t diagnostic_length = strlen(diagnostic);
    for (size_t i = 0; i < diagnostic_length; ++i)
    {
        const unsigned char byte = (unsigned char) diagnostic[i];
        require((byte >= 0x20 && byte < 0x7f) || (byte == '\n' && i + 1 == diagnostic_length),
                "unescaped path control byte reached the diagnostic");
    }

    testCaseSet("long paths retain their generated filename suffix");
    char long_path[1400];
    memset(long_path, 'a', sizeof(long_path));
    memcpy(long_path, directory, strlen(directory));
    memcpy(long_path + strlen(directory), "/missing/", 9);
    memcpy(long_path + sizeof(long_path) - sizeof("-up-12.txt"), "-up-12.txt", sizeof("-up-12.txt"));
    state->all_path = long_path;
    submit(tunnel, payload, true);
    require(strstr(diagnostic, "path_truncated=1") != NULL && strstr(diagnostic, "-up-12.txt\"") != NULL,
            "bounded diagnostic hid truncation or discarded the output suffix");
    require(strlen(diagnostic) < 1400, "long path exceeded the diagnostic path bound");

    testCaseSet("buffered flush failures retain file identity and errno");
    state->all_path = (char *) "/dev/full";
    submit(tunnel, payload, true);
    expectFailure("failed to close output file", "/dev/full", ENOSPC);
    require(strstr(diagnostic, "written_bytes=3") != NULL, "flush failure lost the fwrite result");

    sbufDestroy(payload);
    mutexDestroy(&state->file_mutex);
    tunnelDestroy(tunnel);
    require(rmdir(directory) == 0, "remove isolated temporary directory");
    networkloggerDestroy();
    puts("LoggerTunnel output-file identity, escaping, bounds and native errors passed");
    return 0;
}
