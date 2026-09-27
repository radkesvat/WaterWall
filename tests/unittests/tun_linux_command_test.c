/* Exercise the real TUN command adapter without touching host networking. */
#include "devices/tun/tun_linux_internal.h"
#include "loggers/internal_logger.h"
#include "wwapi.h"

static unsigned int calls;
static unsigned int drops;
static int          outcome;
static char         diagnostic[512];

static void captureDiagnostic(int level, const char *bytes, int length)
{
    discard level;
    size_t  count = min((size_t) max(length, 0), sizeof(diagnostic) - 1U);
    memcpy(diagnostic, bytes, count);
    diagnostic[count] = '\0';
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    if (strcmp(file, "fixture-tool") != 0 || strcmp(argv[0], "fixture-tool") != 0 ||
        strcmp(argv[1], "literal ; $HOME") != 0 || argv[2] != NULL || options->timeout_ms != 7000 ||
        options->terminate_grace_ms != 250 || options->max_output_bytes != 64 * 1024)
    {
        abort();
    }
    ++calls;
    memset(out, 0, sizeof(*out));
    out->exit_code        = outcome == 1 ? 127 : outcome == 5 ? 3 : outcome == 6 ? 143 : 0;
    out->timed_out        = outcome == 2;
    out->output_too_large = outcome == 3;
    out->spawn_failed     = outcome == 4;
    out->output           = memoryAllocate(2);
    strcpy(out->output, "x");
    out->output_len = 1;
    return outcome == 0;
}

void __wrap_procCommandResultDrop(proc_command_result_t *out)
{
    if (out->output == NULL)
    {
        abort();
    }
    ++drops;
    __real_procCommandResultDrop(out);
}

int main(void)
{
    logger_t *logger = loggerCreate();
    if (logger == NULL)
        abort();
    loggerSetHandler(logger, captureDiagnostic);
    setInternalLogger(logger);
    const char *expected[] = {
        "", "status 127", "deadline", "output limit", "supervisor failed", "status 3", "status 143"};
    const char *const argv[] = {"fixture-tool", "literal ; $HOME", NULL};
    for (outcome = 0; outcome <= 6; ++outcome)
    {
        diagnostic[0] = '\0';
        int status    = tunLinuxRunCommandForTest("fixture-tool", argv);
        if (status != (outcome == 0                     ? 0
                       : (outcome == 1 || outcome == 5) ? -1
                                                        : -2) ||
            strstr(diagnostic, expected[outcome]) == NULL)
        {
            abort();
        }
    }
    if (calls != 7 || drops != 7)
    {
        abort();
    }
    internaloggerDestroy();
    return 0;
}
