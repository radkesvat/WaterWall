// Command-wiring coverage for the Linux capture device. The generic process
// runner is replaced with a linker wrap so the exact file/argv/options Capture
// builds can be inspected without opening a real NFQUEUE socket, touching the
// kernel, or requiring root. Packet parsing is covered separately by
// capture_linux_nfqueue_test.c.

#include "devices/capture/capture_linux_internal.h"
#include "wproc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    kMaxRecordedCalls = 32,
    kMaxRecordedArgs  = 16,
    kMaxArgLength     = 128,
    // Capture's own policy constants, duplicated here so the test fails if the
    // production values drift without anyone noticing.
    kExpectedTimeoutMs      = 7000,
    kExpectedGraceMs        = 250,
    kExpectedMaxOutputBytes = 64 * 1024
};

typedef enum fake_outcome_e
{
    kFakeOutcomeSuccess = 0,
    kFakeOutcomeNonzeroExit,
    kFakeOutcomeTimeout,
    kFakeOutcomeSpawnFailure
} fake_outcome_t;

typedef struct recorded_call_s
{
    char                   file[kMaxArgLength];
    char                   argv[kMaxRecordedArgs][kMaxArgLength];
    size_t                 argc;
    proc_command_options_t options;
} recorded_call_t;

static recorded_call_t recorded_calls[kMaxRecordedCalls];
static size_t          recorded_call_count  = 0;
static size_t          dropped_result_count = 0;

// Outcome applied to call index `fail_from_call` onwards; earlier calls succeed.
static fake_outcome_t fake_outcome   = kFakeOutcomeSuccess;
static size_t         fail_from_call = SIZE_MAX;

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void requireEqStr(const char *got, const char *expected, const char *message)
{
    if (strcmp(got, expected) != 0)
    {
        fprintf(stderr, "%s\n  expected: %s\n  got     : %s\n", message, expected, got);
        exit(1);
    }
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    require(file != NULL && argv != NULL && options != NULL && out != NULL,
            "Capture must pass a complete request to the process runner");
    require(recorded_call_count < kMaxRecordedCalls, "too many recorded command calls");

    recorded_call_t *call = &recorded_calls[recorded_call_count];
    memset(call, 0, sizeof(*call));
    snprintf(call->file, sizeof(call->file), "%s", file);
    call->options = *options;
    while (argv[call->argc] != NULL)
    {
        require(call->argc < kMaxRecordedArgs, "too many recorded command arguments");
        snprintf(call->argv[call->argc], sizeof(call->argv[call->argc]), "%s", argv[call->argc]);
        ++call->argc;
    }

    const size_t call_index = recorded_call_count++;

    memset(out, 0, sizeof(*out));
    out->exit_code = -1;

    if (call_index < fail_from_call)
    {
        out->exit_code = 0;
        return true;
    }

    switch (fake_outcome)
    {
    case kFakeOutcomeNonzeroExit:
        out->exit_code = 1;
        return false;
    case kFakeOutcomeTimeout:
        out->timed_out = true;
        return false;
    case kFakeOutcomeSpawnFailure:
        out->spawn_failed = true;
        return false;
    case kFakeOutcomeSuccess:
    default:
        out->exit_code = 0;
        return true;
    }
}

// Counting wrapper proving every result Capture receives is dropped exactly once.
void __wrap_procCommandResultDrop(proc_command_result_t *out)
{
    if (out != NULL)
    {
        ++dropped_result_count;
    }
    __real_procCommandResultDrop(out);
}

static void resetRecording(fake_outcome_t outcome, size_t first_failing_call)
{
    recorded_call_count  = 0;
    dropped_result_count = 0;
    fake_outcome         = outcome;
    fail_from_call       = first_failing_call;
}

static void requireCommonOptions(const recorded_call_t *call, const char *message)
{
    require(call->options.timeout_ms == kExpectedTimeoutMs, message);
    require(call->options.terminate_grace_ms == kExpectedGraceMs, message);
    require(call->options.max_output_bytes == kExpectedMaxOutputBytes, message);
}

static void requireIptablesArgv(const recorded_call_t *call, const char *operation, const char *cidr,
                                const char *queue_number)
{
    static const char *const prefix[] = {"iptables", "-w", "5"};
    static const char *const suffix[] = {"INPUT", "-s"};

    require(call->argc == 11, "the iptables argv must have exactly eleven elements");
    requireEqStr(call->file, "iptables", "iptables must be executed by name through execvp");
    for (size_t i = 0; i < sizeof(prefix) / sizeof(prefix[0]); ++i)
    {
        requireEqStr(call->argv[i], prefix[i], "iptables argv prefix mismatch");
    }
    requireEqStr(call->argv[3], operation, "iptables operation mismatch");
    for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); ++i)
    {
        requireEqStr(call->argv[4 + i], suffix[i], "iptables chain/source argv mismatch");
    }
    requireEqStr(call->argv[6], cidr, "iptables source CIDR mismatch");
    requireEqStr(call->argv[7], "-j", "iptables jump flag mismatch");
    requireEqStr(call->argv[8], "NFQUEUE", "iptables jump target mismatch");
    requireEqStr(call->argv[9], "--queue-num", "iptables queue flag mismatch");
    requireEqStr(call->argv[10], queue_number, "iptables queue number mismatch");
}

// Nothing Capture runs may be handed to a shell: neither the executable nor any
// argument may be a shell or a reconstructed command string.
static void requireNoShellInvocation(void)
{
    for (size_t i = 0; i < recorded_call_count; ++i)
    {
        const recorded_call_t *call = &recorded_calls[i];
        require(strstr(call->file, "/bin/sh") == NULL && strcmp(call->file, "sh") != 0,
                "Capture must never execute a shell");
        for (size_t a = 0; a < call->argc; ++a)
        {
            require(strcmp(call->argv[a], "-c") != 0, "Capture must never pass a shell command string");
        }
    }
}

static void testInsertBuildsExactArgv(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceRunIptablesQueueRule("-I", "10.0.0.0/8", 7) == kCapturedeviceCommandOk,
            "a clean iptables insertion must succeed");
    require(recorded_call_count == 1, "insertion must run exactly one command");
    requireIptablesArgv(&recorded_calls[0], "-I", "10.0.0.0/8", "7");
    requireCommonOptions(&recorded_calls[0], "insertion must use Capture's configured deadline, grace, and output cap");
    requireNoShellInvocation();
    require(dropped_result_count == 1, "insertion must drop its command result exactly once");
}

static void testDeleteBuildsExactArgv(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceRunIptablesQueueRule("-D", "192.168.1.0/24", 12) == kCapturedeviceCommandOk,
            "a clean iptables deletion must succeed");
    require(recorded_call_count == 1, "deletion must run exactly one command");
    requireIptablesArgv(&recorded_calls[0], "-D", "192.168.1.0/24", "12");
    requireCommonOptions(&recorded_calls[0], "deletion must use the same wait and deadline policy as insertion");
    requireNoShellInvocation();
    require(dropped_result_count == 1, "deletion must drop its command result exactly once");
}

static void testIptablesTimeoutIsDistinctFromNonzeroExit(void)
{
    resetRecording(kFakeOutcomeNonzeroExit, 0);
    require(capturedeviceRunIptablesQueueRule("-D", "10.0.0.0/8", 1) == kCapturedeviceCommandFailed,
            "a nonzero iptables exit must report a plain command failure");
    require(dropped_result_count == 1, "a failed command must still drop its result exactly once");

    resetRecording(kFakeOutcomeTimeout, 0);
    require(capturedeviceRunIptablesQueueRule("-D", "10.0.0.0/8", 1) == kCapturedeviceCommandTimedOut,
            "an iptables timeout must be distinguishable from a nonzero exit");
    require(dropped_result_count == 1, "a timed-out command must still drop its result exactly once");

    resetRecording(kFakeOutcomeSpawnFailure, 0);
    require(capturedeviceRunIptablesQueueRule("-I", "10.0.0.0/8", 1) == kCapturedeviceCommandSpawnFailed,
            "a spawn failure must be distinguishable from a nonzero exit");
    require(dropped_result_count == 1, "a spawn-failed command must still drop its result exactly once");
}

static void testSysctlUsesDirectArgvWithGroupedValues(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    capturedeviceApplySysctls();
    require(recorded_call_count > 1, "the sysctl batch must apply every setting");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");
    requireNoShellInvocation();

    bool found_multi_value = false;
    for (size_t i = 0; i < recorded_call_count; ++i)
    {
        const recorded_call_t *call = &recorded_calls[i];
        requireEqStr(call->file, "sysctl", "sysctl must be executed by name through execvp");
        require(call->argc == 3, "each sysctl command must be exactly `sysctl -w <setting>`");
        requireEqStr(call->argv[0], "sysctl", "sysctl argv[0] mismatch");
        requireEqStr(call->argv[1], "-w", "sysctl must use the -w write flag");
        requireCommonOptions(call, "sysctl must use Capture's configured deadline, grace, and output cap");

        if (strcmp(call->argv[2], "net.ipv4.tcp_rmem=4096 87380 134217728") == 0)
        {
            found_multi_value = true;
        }
    }
    require(found_multi_value, "a multi-value sysctl setting must arrive as one argv element after -w");
}

static void testSysctlNonzeroExitStaysBestEffort(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    capturedeviceApplySysctls();
    const size_t total_settings = recorded_call_count;

    // Fail the very first setting with an ordinary nonzero exit: the batch must
    // still attempt every remaining setting.
    resetRecording(kFakeOutcomeNonzeroExit, 0);
    capturedeviceApplySysctls();
    require(recorded_call_count == total_settings, "a normal sysctl failure must remain best-effort");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");
}

static void testSysctlTimeoutStopsTheRestOfTheBatch(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    capturedeviceApplySysctls();
    const size_t total_settings = recorded_call_count;
    require(total_settings > 2, "the sysctl batch must contain enough settings for this test");

    // Time out on the second setting: the first is attempted, the second hangs,
    // and nothing after it is retried.
    resetRecording(kFakeOutcomeTimeout, 1);
    capturedeviceApplySysctls();
    require(recorded_call_count == 2, "a sysctl timeout must stop the rest of the tuning batch");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");

    // A parent-side spawn failure stops the batch for the same reason.
    resetRecording(kFakeOutcomeSpawnFailure, 0);
    capturedeviceApplySysctls();
    require(recorded_call_count == 1, "a sysctl spawn failure must stop the rest of the tuning batch");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");
}

int main(void)
{
    testInsertBuildsExactArgv();
    testDeleteBuildsExactArgv();
    testIptablesTimeoutIsDistinctFromNonzeroExit();
    testSysctlUsesDirectArgvWithGroupedValues();
    testSysctlNonzeroExitStaysBestEffort();
    testSysctlTimeoutStopsTheRestOfTheBatch();

    printf("capture_linux_command_test: all tests passed\n");
    return 0;
}
