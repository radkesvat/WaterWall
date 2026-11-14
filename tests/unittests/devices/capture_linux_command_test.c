/*
 * Covers: capture linux command; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Cases: testInsertBuildsExactArgv, testDeleteBuildsExactArgv,
 * testEarlyQueueInspectionUsesRawPrerouting, testIptablesTimeoutIsDistinctFromNonzeroExit,
 * testInputInspectionUsesLargeSnapshotCap, testInputInspectionRejectsEmptySnapshot,
 * testQueueSelectionAvoidsReferencedNumbers; the driver lists the remaining cases
 * Checks: Assertion labels include: Capture must pass a complete request to the process runner; too many
 * recorded command calls; too many recorded command arguments; the iptables argv must have exactly
 * twenty-two elements
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.capture_linux_command_unit
 */
// Command-wiring coverage for the Linux capture device. The generic process
// runner is replaced with a linker wrap so the exact file/argv/options Capture
// builds can be inspected without opening a real NFQUEUE socket, touching the
// kernel, or requiring root. Packet parsing is covered separately by
// capture_linux_nfqueue_test.c.

#include "devices/capture/capture_linux_internal.h"
#include "devices/capture/capture_linux_rules.h"

#include "test_assert.h"

#define require(condition, message)             TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#define requireEqStr(actual, expected, message) TEST_EQUAL_TEXT(TEST_FAILURE_EXIT, actual, expected, message)
#include "wwapi.h"
#include <linux/filter.h>
#include <sys/socket.h>
#include <unistd.h>

enum
{
    kMaxRecordedCalls = 32,
    kMaxRecordedArgs  = 40,
    kMaxArgLength     = kCaptureLinuxSteeringFilterSize,
    // Capture's own policy constants, duplicated here so the test fails if the
    // production values drift without anyone noticing.
    kExpectedTimeoutMs                = 7000,
    kExpectedGraceMs                  = 250,
    kExpectedMutationMaxOutputBytes   = 64 * 1024,
    kExpectedInspectionMaxOutputBytes = 1024 * 1024
};

typedef enum fake_outcome_e
{
    kFakeOutcomeSuccess = 0,
    kFakeOutcomeNonzeroExit,
    kFakeOutcomeTimeout,
    kFakeOutcomeSpawnFailure,
    kFakeOutcomeOutputTooLarge
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
static const char    *fake_success_output;
static const char    *fake_prerouting_output;
static size_t         fake_success_output_len;
static bool           fake_reader_operational   = true;
static size_t         reader_failure_after_call = SIZE_MAX;

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);
bool __wrap_capturedeviceReaderOperational(capture_device_t *cdev);

bool __wrap_capturedeviceReaderOperational(capture_device_t *cdev)
{
    require(cdev != NULL, "reader operational check lost its device");
    return fake_reader_operational;
}

static bool completeSuccessfulCommand(proc_command_result_t *out, bool prerouting)
{
    out->exit_code = 0;
    const char *output = prerouting && fake_prerouting_output != NULL ? fake_prerouting_output : fake_success_output;
    if (output != NULL)
    {
        const size_t length = output == fake_success_output ? fake_success_output_len : stringLength(output);
        out->output         = memoryAllocate(length + 1U);
        memoryCopy(out->output, output, length);
        out->output[length] = '\0';
        out->output_len     = length;
    }
    return true;
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

    const bool   prerouting = call->argc > 5 && strcmp(argv[4], "raw") == 0 && strcmp(argv[5], "-S") == 0;
    const size_t call_index = recorded_call_count++;
    if (recorded_call_count >= reader_failure_after_call)
    {
        fake_reader_operational = false;
    }

    memset(out, 0, sizeof(*out));
    out->exit_code = -1;

    if (call_index < fail_from_call)
    {
        return completeSuccessfulCommand(out, prerouting);
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
    case kFakeOutcomeOutputTooLarge:
        out->output_too_large = true;
        return false;
    case kFakeOutcomeSuccess:
    default:
        return completeSuccessfulCommand(out, prerouting);
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
    recorded_call_count       = 0;
    dropped_result_count      = 0;
    fake_outcome              = outcome;
    fail_from_call            = first_failing_call;
    fake_success_output       = NULL;
    fake_prerouting_output    = NULL;
    fake_success_output_len   = 0;
    fake_reader_operational   = true;
    reader_failure_after_call = SIZE_MAX;
}

static void requireMutationOptions(const recorded_call_t *call, const char *message)
{
    require(call->options.timeout_ms == kExpectedTimeoutMs, message);
    require(call->options.terminate_grace_ms == kExpectedGraceMs, message);
    require(call->options.max_output_bytes == kExpectedMutationMaxOutputBytes, message);
}

static void requireInspectionOptions(const recorded_call_t *call, const char *message)
{
    require(call->options.timeout_ms == kExpectedTimeoutMs, message);
    require(call->options.terminate_grace_ms == kExpectedGraceMs, message);
    require(call->options.max_output_bytes == kExpectedInspectionMaxOutputBytes, message);
}

static void requireIptablesArgv(const recorded_call_t *call, const char *operation, const char *cidr,
                                const char *queue_number, const char *rule_comment)
{
    const char *const expected[] = {"iptables",   "-w",
                                    "5",          "-t",
                                    "raw",        operation,
                                    "PREROUTING", "-s",
                                    cidr,         "-m",
                                    "addrtype",   "--dst-type",
                                    "LOCAL",      "-m",
                                    "comment",    "--comment",
                                    rule_comment, "-j",
                                    "NFQUEUE",    "--queue-num",
                                    queue_number, "--queue-bypass"};
    requireEqStr(call->file, "iptables", "iptables must be executed directly");
    require(call->argc == ARRAY_SIZE(expected), "capture rule argument count mismatch");
    for (size_t i = 0; i < ARRAY_SIZE(expected); ++i)
        requireEqStr(call->argv[i], expected[i], "capture rule must use raw PREROUTING and local-unicast scope");
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
    require(capturedeviceRunIptablesQueueRule("-I", "10.0.0.0/8", 7, "WWCAP_TEST_INSERT", "") ==
                kCapturedeviceCommandOk,
            "a clean iptables insertion must succeed");
    require(recorded_call_count == 1, "insertion must run exactly one command");
    requireIptablesArgv(&recorded_calls[0], "-I", "10.0.0.0/8", "7", "WWCAP_TEST_INSERT");
    requireMutationOptions(&recorded_calls[0],
                           "insertion must use Capture's configured deadline, grace, and mutation output cap");
    requireNoShellInvocation();
    require(dropped_result_count == 1, "insertion must drop its command result exactly once");
}

static void testDeleteBuildsExactArgv(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceRunIptablesQueueRule("-D", "192.168.1.0/24", 12, "WWCAP_TEST_DELETE", "") ==
                kCapturedeviceCommandOk,
            "a clean iptables deletion must succeed");
    require(recorded_call_count == 1, "deletion must run exactly one command");
    requireIptablesArgv(&recorded_calls[0], "-D", "192.168.1.0/24", "12", "WWCAP_TEST_DELETE");
    requireMutationOptions(&recorded_calls[0], "deletion must use the same wait and deadline policy as insertion");
    requireNoShellInvocation();
    require(dropped_result_count == 1, "deletion must drop its command result exactly once");
}

static void testEarlyQueueInspectionUsesRawPrerouting(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_success_output     = "-P PREROUTING ACCEPT\n";
    fake_success_output_len = strlen(fake_success_output);
    char *rules             = NULL;
    require(capturedeviceReadIptablesPreroutingRules(&rules) == kCapturedeviceCommandOk,
            "early queue rule inspection failed");
    requireEqStr(rules, fake_success_output, "early queue inspection lost its snapshot");
    memoryFree(rules);

    const char *const expected[] = {"iptables", "-w", "5", "-t", "raw", "-S", "PREROUTING"};
    require(recorded_call_count == 1, "early queue inspection must issue exactly one command");
    require(recorded_calls[0].argc == sizeof(expected) / sizeof(expected[0]),
            "early queue inspection argument count mismatch");
    for (size_t i = 0; i < recorded_calls[0].argc; ++i)
    {
        requireEqStr(recorded_calls[0].argv[i], expected[i], "early queue inspection queried the wrong chain/table");
    }
    requireInspectionOptions(&recorded_calls[0], "early queue inspection used the wrong command bounds");
    require(dropped_result_count == 1, "early queue inspection leaked its command result");

    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    rules = NULL;
    require(capturedeviceReadIptablesPreroutingRules(&rules) == kCapturedeviceCommandFailed && rules == NULL,
            "early queue inspection must reject a lost snapshot");
}

static void testIptablesTimeoutIsDistinctFromNonzeroExit(void)
{
    resetRecording(kFakeOutcomeNonzeroExit, 0);
    require(capturedeviceRunIptablesQueueRule("-D", "10.0.0.0/8", 1, "WWCAP_TEST_STATUS", "") ==
                kCapturedeviceCommandFailed,
            "a nonzero iptables exit must report a plain command failure");
    require(dropped_result_count == 1, "a failed command must still drop its result exactly once");

    resetRecording(kFakeOutcomeTimeout, 0);
    require(capturedeviceRunIptablesQueueRule("-D", "10.0.0.0/8", 1, "WWCAP_TEST_STATUS", "") ==
                kCapturedeviceCommandTimedOut,
            "an iptables timeout must be distinguishable from a nonzero exit");
    require(dropped_result_count == 1, "a timed-out command must still drop its result exactly once");

    resetRecording(kFakeOutcomeSpawnFailure, 0);
    require(capturedeviceRunIptablesQueueRule("-I", "10.0.0.0/8", 1, "WWCAP_TEST_STATUS", "") ==
                kCapturedeviceCommandSpawnFailed,
            "a spawn failure must be distinguishable from a nonzero exit");
    require(dropped_result_count == 1, "a spawn-failed command must still drop its result exactly once");

    resetRecording(kFakeOutcomeOutputTooLarge, 0);
    require(capturedeviceRunIptablesQueueRule("-I", "10.0.0.0/8", 1, "WWCAP_TEST_STATUS", "") ==
                kCapturedeviceCommandOutputTooLarge,
            "output-limit termination must be distinguishable from a nonzero exit");
    require(dropped_result_count == 1, "an output-limited command must still drop its result exactly once");
}

static void testInputInspectionUsesLargeSnapshotCap(void)
{
    static const char rule[]         = "-A INPUT -j ACCEPT\n";
    const size_t      target_size    = 80U * 1024U;
    char             *large_snapshot = memoryAllocate(target_size + 1U);
    size_t            length         = 0;
    while (length + sizeof(rule) - 1U <= target_size)
    {
        memoryCopy(large_snapshot + length, rule, sizeof(rule) - 1U);
        length += sizeof(rule) - 1U;
    }
    large_snapshot[length] = '\0';

    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_success_output     = large_snapshot;
    fake_success_output_len = length;

    char *captured = NULL;
    require(capturedeviceReadIptablesInputRules(&captured) == kCapturedeviceCommandOk,
            "a valid INPUT snapshot larger than the mutation cap must be accepted");
    require(captured != NULL && stringLength(captured) > kExpectedMutationMaxOutputBytes,
            "the large INPUT snapshot was not transferred intact");
    require(recorded_call_count == 1, "INPUT inspection must run exactly one command");
    requireInspectionOptions(&recorded_calls[0], "INPUT inspection did not use its separate one-megabyte cap");
    require(recorded_calls[0].argc == 7, "INPUT inspection argv must be `iptables -w 5 -t filter -S INPUT`");
    requireEqStr(recorded_calls[0].argv[5], "-S", "INPUT inspection must use the list-rules operation");
    requireEqStr(recorded_calls[0].argv[6], "INPUT", "INPUT inspection must target the INPUT chain");
    require(dropped_result_count == 1, "INPUT inspection must drop its transferred command result exactly once");

    memoryFree(captured);
    memoryFree(large_snapshot);
    fake_success_output     = NULL;
    fake_success_output_len = 0;
}

static void testInputInspectionRejectsEmptySnapshot(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_success_output     = "";
    fake_success_output_len = 0;

    char *captured = NULL;
    require(capturedeviceReadIptablesInputRules(&captured) == kCapturedeviceCommandFailed,
            "a clean empty INPUT snapshot must be rejected as lost output");
    require(captured == NULL, "a rejected empty INPUT snapshot must not transfer ownership");
    require(recorded_call_count == 1, "empty INPUT inspection must run exactly one command");
    requireInspectionOptions(&recorded_calls[0], "empty INPUT inspection must retain the inspection output cap");
    require(dropped_result_count == 1, "empty INPUT inspection must drop its command result exactly once");
}

static void testQueueSelectionAvoidsReferencedNumbers(void)
{
    const char *snapshot = "-A INPUT -j NFQUEUE --queue-num 7 --queue-bypass\n"
                           "-A INPUT -j NFQUEUE --queue-balance 10:12 --queue-bypass\n"
                           "-A INPUT -j NFQUEUE --queue-num 65535 --queue-bypass\n"
                           "-A INPUT -j NFQUEUE --queue-num 0 --queue-bypass\n";
    uint16_t    selected = 0;

    require(capturedeviceSelectUnusedQueueNumber(snapshot, "", 7, &selected) && selected == 8,
            "queue selection did not skip an exact stale queue reference");
    require(capturedeviceSelectUnusedQueueNumber(snapshot, "", 10, &selected) && selected == 13,
            "queue selection did not skip an existing queue-balance range");
    require(capturedeviceSelectUnusedQueueNumber(snapshot, "", UINT16_MAX, &selected) && selected == 1,
            "queue selection did not skip stale queue references across uint16 wraparound");
}

static void testQueueRangeSelection(void)
{
    const char *snapshot = "-A INPUT -j NFQUEUE --queue-num 0\n"
                           "-A INPUT -j NFQUEUE --queue-num 8\n"
                           "-A INPUT -j NFQUEUE --queue-balance 12:14\n";
    uint16_t    selected = 0;
    require(capturedeviceSelectUnusedQueueRange(snapshot, "", 7, 3, &selected) && selected == 9,
            "queue range selection did not skip an overlapping single queue");
    require(capturedeviceSelectUnusedQueueRange(snapshot, "", 10, 3, &selected) && selected == 15,
            "queue range selection did not skip an overlapping balanced range");
    require(capturedeviceSelectUnusedQueueRange(snapshot, "", UINT16_MAX - 1, 3, &selected) && selected == 1,
            "queue range wrapped across 65535 instead of selecting a contiguous range");
    require(capturedeviceSelectUnusedQueueRange("-P INPUT ACCEPT\n", "", UINT16_MAX - 2, 3, &selected) &&
                selected == UINT16_MAX - 2,
            "queue range ending exactly at 65535 was rejected");
    selected = 123;
    require(
        ! capturedeviceSelectUnusedQueueRange("-A INPUT -j NFQUEUE --queue-balance 0:65534\n", "", 0, 2, &selected) &&
            selected == 123,
        "queue range exhaustion changed the caller's selection or accepted a partial range");
    const char *early = "-A PREROUTING -j NFQUEUE --queue-num 9\n"
                        "-A PREROUTING -j NFQUEUE --queue-balance 15:17\n";
    require(capturedeviceSelectUnusedQueueRange(snapshot, early, 7, 3, &selected) && selected == 18,
            "selection reused an INPUT or raw PREROUTING reference");
    require(capturedeviceSelectUnusedQueueNumber("", early, 15, &selected) && selected == 18,
            "selection ignored an early balanced queue range");
}

static void testQueueSelectionInspectsBothHooks(void)
{
    const uint16_t saved_start              = GSTATE.capturedevice_queue_start_number;
    GSTATE.capturedevice_queue_start_number = 7;
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_success_output     = "-A INPUT -j NFQUEUE --queue-num 7\n";
    fake_success_output_len = stringLength(fake_success_output);
    fake_prerouting_output  = "-A PREROUTING -j NFQUEUE --queue-num 8\n";
    uint16_t selected       = 123;
    require(capturedeviceChooseQueueRange(1, &selected) && selected == 9,
            "queue setup did not exclude both hooks' stale rules");
    require(recorded_call_count == 2 && dropped_result_count == 2, "queue setup did not inspect both hooks once");
    requireEqStr(recorded_calls[0].argv[6], "INPUT", "queue setup did not inspect INPUT");
    requireEqStr(recorded_calls[1].argv[4], "raw", "queue setup did not inspect raw");
    requireEqStr(recorded_calls[1].argv[6], "PREROUTING", "queue setup did not inspect PREROUTING");
    for (size_t failure = 0; failure < 2; ++failure)
    {
        resetRecording(kFakeOutcomeTimeout, failure);
        fake_success_output     = "-P INPUT ACCEPT\n";
        fake_success_output_len = stringLength(fake_success_output);
        selected                = 123;
        require(! capturedeviceChooseQueueRange(1, &selected) && selected == 123,
                "queue selection used incomplete firewall evidence");
        require(recorded_call_count == failure + 1 && dropped_result_count == failure + 1,
                "failed queue inspection leaked its result or continued");
    }
    GSTATE.capturedevice_queue_start_number = saved_start;
}

enum
{
    kRuleTestRanges = 2,
    kRuleTestQueues = 3
};

typedef struct capture_rule_fixture_s
{
    capture_device_t            device;
    capture_linux_queue_t       queues[kRuleTestQueues];
    capture_range_rule_states_t states[kRuleTestRanges * kRuleTestQueues];
    char                       *cidrs[kRuleTestRanges];
} capture_rule_fixture_t;

static void prepareRuleFixture(capture_rule_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->cidrs[0] = (char *) "192.0.2.0/24";
    fixture->cidrs[1] = (char *) "198.51.100.0/24";
    fixture->device   = (capture_device_t) {.queue_count         = kRuleTestQueues,
                                            .opaque_flow_mode    = kDeviceOpaqueFlowSpread,
                                            .queues              = fixture->queues,
                                            .capture_cidrs       = fixture->cidrs,
                                            .capture_range_count = kRuleTestRanges,
                                            .rule_states         = fixture->states,
                                            .rule_token          = UINT64_C(0x1234567890ABCDEF)};
    for (uint16_t lane = 0; lane < kRuleTestQueues; ++lane)
    {
        fixture->queues[lane].fd     = -1;
        fixture->queues[lane].number = 70 + lane;
        captureLinuxBuildSteeringFilter(
            kRuleTestQueues, lane, fixture->device.opaque_flow_mode, fixture->queues[lane].steering_filter);
    }
    capture_protocol_filter_t protocol_filter = {0};
    captureProtocolFilterExclude(&protocol_filter, 6);
    captureLinuxBuildProtocolFilter(&protocol_filter, fixture->device.protocol_filter);
}

static void requireRuleProgress(const recorded_call_t *call, capture_device_t *device)
{
    require(call->options.progress == captureReaderService && call->options.progress_context == device,
            "owned firewall command lost inactive queue service");
}

static void requireMatchingDelete(const recorded_call_t *insert, const recorded_call_t *remove, size_t operation)
{
    require(insert->argc == remove->argc, "rule deletion changed its predicate argument count");
    requireEqStr(remove->argv[operation], "-D", "cleanup did not delete the owned rule");
    for (size_t arg = 0; arg < insert->argc; ++arg)
    {
        if (arg != operation)
        {
            requireEqStr(insert->argv[arg], remove->argv[arg], "rule deletion changed its owned identity or predicate");
        }
    }
}

static void testDeterministicModesInstallOnlyOwnedFlowRules(void)
{
    for (device_opaque_flow_mode_t mode = kDeviceOpaqueFlowPrefix; mode <= kDeviceOpaqueFlowPeer; ++mode)
    {
        capture_rule_fixture_t fixture;
        prepareRuleFixture(&fixture);
        fixture.device.opaque_flow_mode = mode;
        for (uint16_t lane = 0; lane < kRuleTestQueues; ++lane)
            captureLinuxBuildSteeringFilter(kRuleTestQueues, lane, mode, fixture.queues[lane].steering_filter);
        resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
        require(capturedeviceInstallRules(&fixture.device), "deterministic mode installation failed");
        require(recorded_call_count == kRuleTestRanges * kRuleTestQueues,
                "deterministic mode installed random opaque rules");
        for (size_t i = 0; i < recorded_call_count; ++i)
        {
            require(fixture.states[i].queue == kCaptureRuleInstalled && fixture.states[i].opaque == kCaptureRuleAbsent,
                    "deterministic mode published the wrong rule inventory");
            require(recorded_calls[i].argc == 30, "deterministic rule acquired statistic matcher arguments");
        }
        require(capturedeviceRemoveInstalledRules(&fixture.device), "deterministic mode cleanup failed");
        require(capturedevicePendingRangeCount(&fixture.device) == 0, "deterministic mode retained rule ownership");
    }
}

static void testMultiqueueRulesRetainExactLifecycle(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceInstallRules(&fixture.device), "multiqueue rule installation failed");
    require(recorded_call_count == 12, "multiqueue rules did not install both lane sets");
    require(capturedevicePendingRangeCount(&fixture.device) == kRuleTestRanges,
            "pending accounting counted queue lanes as capture ranges");
    for (size_t index = 0; index < kRuleTestRanges * kRuleTestQueues; ++index)
    {
        const recorded_call_t *call = &recorded_calls[index];
        const size_t           lane = index % kRuleTestQueues;
        char                   queue_number[16];
        char                   comment[48];
        stringNPrintf(queue_number, sizeof(queue_number), "%u", fixture.queues[lane].number);
        stringNPrintf(comment, sizeof(comment), "WWCAP_1234567890ABCDEF_%016zX", index);
        requireEqStr(
            call->argv[8], fixture.cidrs[index / kRuleTestQueues], "queue lane matched the wrong source range");
        requireEqStr(call->argv[16], comment, "queue lane did not get a unique rule comment");
        requireEqStr(call->argv[20], queue_number, "queue lane targeted the wrong NFQUEUE");
        require(call->argc == 30, "multiqueue rule did not keep two independent BPF predicates");
        requireEqStr(call->argv[25], fixture.device.protocol_filter, "queue lane changed the protocol exclusion");
        requireEqStr(call->argv[29], fixture.queues[lane].steering_filter, "queue lane changed the steering predicate");
        require(fixture.states[index].queue == kCaptureRuleInstalled, "queue rule state was not published");
        const recorded_call_t *opaque = &recorded_calls[6 + index];
        char                   opaque_filter[kCaptureLinuxSteeringFilterSize];
        captureLinuxBuildOpaqueFilter(opaque_filter);
        stringNPrintf(comment, sizeof(comment), "WWCAP_OPAQUE_1234567890ABCDEF_%016zX", index);
        requireEqStr(opaque->argv[16], comment, "opaque queue lost its independent owned identity");
        requireEqStr(opaque->argv[20], queue_number, "opaque queue targeted the wrong lane");
        requireEqStr(opaque->argv[25], fixture.device.protocol_filter, "opaque queue lost protocol exclusions");
        requireEqStr(opaque->argv[29], opaque_filter, "opaque queue lost its disjoint classification");
        require(opaque->argc == (lane == 0 ? 30 : 36), "opaque queue has incorrect random arguments or no tail");
        if (lane != 0)
        {
            const char *probability = lane == 1 ? "0.500000000000" : "0.333333333333";
            requireEqStr(opaque->argv[30], "-m", "opaque queue omitted statistic module option");
            requireEqStr(opaque->argv[31], "statistic", "opaque queue omitted kernel statistic matcher");
            requireEqStr(opaque->argv[32], "--mode", "opaque queue omitted statistic mode option");
            requireEqStr(opaque->argv[33], "random", "opaque receive retained a shared nth counter");
            requireEqStr(opaque->argv[34], "--probability", "opaque queue omitted its conditional probability");
            requireEqStr(
                opaque->argv[35], probability, "random cascade probability does not match reverse INSERT order");
        }
        require(fixture.states[index].opaque == kCaptureRuleInstalled, "opaque rule state was not published");
    }
    require(capturedeviceRemoveInstalledRules(&fixture.device), "multiqueue cleanup failed");
    require(recorded_call_count == 24 && capturedevicePendingRangeCount(&fixture.device) == 0,
            "multiqueue cleanup did not retire every owned rule exactly once");
    for (size_t index = 0; index < 6; ++index)
    {
        requireMatchingDelete(&recorded_calls[11 - index], &recorded_calls[12 + index], 5);
        requireMatchingDelete(&recorded_calls[5 - index], &recorded_calls[18 + index], 5);
    }
    for (size_t call = 0; call < recorded_call_count; ++call)
    {
        requireRuleProgress(&recorded_calls[call], &fixture.device);
    }
    requireNoShellInvocation();
}

static void testUnknownInsertReconciliation(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    /* Reconcile a possibly committed early rule in the same table, including
     * the case where the failed command did not actually install it. */
    for (unsigned present = 0; present < 2; ++present)
    {
        resetRecording(kFakeOutcomeTimeout, 1);
        require(! capturedeviceInstallRules(&fixture.device), "unknown early insertion was accepted");
        require(fixture.states[0].queue == kCaptureRuleInstalled &&
                    fixture.states[1].queue == kCaptureRuleOutcomeUnknown,
                "early insertion lost ownership");
        char snapshot[128];
        stringNPrintf(snapshot,
                      sizeof(snapshot),
                      present
                          ? "-A PREROUTING -m comment --comment WWCAP_1234567890ABCDEF_0000000000000001 -j NFQUEUE\n"
                          : "-P PREROUTING ACCEPT\n");
        resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
        fake_success_output     = snapshot;
        fake_success_output_len = stringLength(snapshot);
        require(capturedeviceRemoveInstalledRules(&fixture.device), "early reconciliation failed");
        require(recorded_call_count == 2U + present && capturedevicePendingRangeCount(&fixture.device) == 0,
                "early reconciliation deleted an absent rule or missed a present one");
        requireEqStr(recorded_calls[0].argv[4], "raw", "early reconciliation read the wrong table");
        requireEqStr(recorded_calls[0].argv[5], "-S", "early reconciliation did not inspect rules");
        requireEqStr(recorded_calls[0].argv[6], "PREROUTING", "early reconciliation read the wrong chain");
    }
}

static void testMultiqueuePartialInstallReconciliation(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    resetRecording(kFakeOutcomeTimeout, 1);
    require(! capturedeviceInstallRules(&fixture.device), "timed-out queue insertion was accepted");
    require(recorded_call_count == 2 && fixture.states[0].queue == kCaptureRuleInstalled &&
                fixture.states[1].queue == kCaptureRuleOutcomeUnknown && fixture.states[2].queue == kCaptureRuleAbsent,
            "partial multiqueue insertion lost exact known and unknown ownership");
    require(capturedevicePendingRangeCount(&fixture.device) == 1, "partial insertion counted the untouched range");

    char snapshot[kMaxArgLength + 64];
    stringNPrintf(
        snapshot, sizeof(snapshot), "-A PREROUTING -m comment --comment %s -j NFQUEUE\n", recorded_calls[1].argv[16]);
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_success_output     = snapshot;
    fake_success_output_len = stringLength(snapshot);
    require(capturedeviceRemoveInstalledRules(&fixture.device), "reconciled partial multiqueue cleanup failed");
    require(recorded_call_count == 3 && capturedevicePendingRangeCount(&fixture.device) == 0,
            "partial cleanup did not inspect once and delete exactly two rules");
    requireEqStr(recorded_calls[0].argv[5], "-S", "unknown queue outcome was not inspected before deletion");
    requireEqStr(recorded_calls[1].argv[20], "71", "unknown queue lane was not retired first");
    requireEqStr(recorded_calls[2].argv[20], "70", "previously installed queue lane was not retired");
    for (size_t call = 0; call < recorded_call_count; ++call)
    {
        requireRuleProgress(&recorded_calls[call], &fixture.device);
    }
}

static void testOpaqueFailureStillRemovesFlowRules(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    for (size_t index = 0; index < ARRAY_SIZE(fixture.states); ++index)
    {
        fixture.states[index].queue = kCaptureRuleInstalled;
    }
    fixture.states[0].opaque               = kCaptureRuleInstalled;
    fixture.states[kRuleTestQueues].opaque = kCaptureRuleInstalled;
    resetRecording(kFakeOutcomeNonzeroExit, 0);
    require(! capturedeviceRemoveInstalledRules(&fixture.device), "failed cleanup was accepted");
    require(recorded_call_count == 2, "opaque failure prevented the independent flow cleanup attempt");
    require(strstr(recorded_calls[0].argv[16], "WWCAP_OPAQUE_") != NULL, "cleanup did not attempt opaque first");
    require(strstr(recorded_calls[1].argv[16], "WWCAP_OPAQUE_") == NULL, "cleanup did not attempt flow rules");
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceRemoveInstalledRules(&fixture.device) && capturedevicePendingRangeCount(&fixture.device) == 0,
            "cleanup retry did not settle retained rule ownership");
    require(recorded_call_count == 8, "cleanup retry changed the exact retained rule inventory");
}

static void testOpaqueUnknownInstallCleanup(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    resetRecording(kFakeOutcomeTimeout, 7);
    require(! capturedeviceInstallRules(&fixture.device), "unknown opaque insertion was accepted");
    require(fixture.states[0].opaque == kCaptureRuleInstalled &&
                fixture.states[1].opaque == kCaptureRuleOutcomeUnknown &&
                fixture.states[2].opaque == kCaptureRuleAbsent,
            "partial opaque insertion lost exact ownership");
    char snapshot[kMaxArgLength + 64];
    stringNPrintf(
        snapshot, sizeof(snapshot), "-A PREROUTING -m comment --comment %s -j NFQUEUE\n", recorded_calls[7].argv[16]);
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_success_output     = snapshot;
    fake_success_output_len = stringLength(snapshot);
    require(capturedeviceRemoveInstalledRules(&fixture.device) && capturedevicePendingRangeCount(&fixture.device) == 0,
            "opaque outcome reconciliation did not retire both rule sets");
    require(recorded_call_count == 9 && strstr(recorded_calls[1].argv[16], "WWCAP_OPAQUE_") != NULL &&
                strstr(recorded_calls[3].argv[16], "WWCAP_OPAQUE_") == NULL,
            "opaque cleanup inspected or removed the wrong rule family");
    require(recorded_calls[1].argc == 36 && recorded_calls[2].argc == 30,
            "unknown insertion cleanup lost the random rule or unconditional tail");
    requireEqStr(recorded_calls[1].argv[33], "random", "unknown insertion cleanup changed the statistic mode");
    requireEqStr(recorded_calls[1].argv[35], "0.500000000000", "unknown insertion cleanup changed probability");
}

static void testMultiqueueUnknownDeleteReconciliation(void)
{
    for (unsigned int present = 0; present < 2; ++present)
    {
        capture_rule_fixture_t fixture;
        prepareRuleFixture(&fixture);
        for (size_t index = 0; index < ARRAY_SIZE(fixture.states); ++index)
        {
            fixture.states[index].queue = kCaptureRuleInstalled;
        }
        resetRecording(kFakeOutcomeTimeout, 2);
        require(! capturedeviceRemoveInstalledRules(&fixture.device), "timed-out deletion was accepted");
        require(recorded_call_count == 3 && fixture.states[5].queue == kCaptureRuleAbsent &&
                    fixture.states[4].queue == kCaptureRuleAbsent &&
                    fixture.states[3].queue == kCaptureRuleOutcomeUnknown &&
                    fixture.states[2].queue == kCaptureRuleInstalled,
                "partial deletion lost the exact per-lane ownership boundary");
        char snapshot[kMaxArgLength + 64];
        if (present != 0)
        {
            stringNPrintf(snapshot,
                          sizeof(snapshot),
                          "-A PREROUTING -m comment --comment %s -j NFQUEUE\n",
                          recorded_calls[2].argv[16]);
        }
        else
        {
            stringNPrintf(snapshot, sizeof(snapshot), "-P PREROUTING ACCEPT\n");
        }

        resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
        fake_success_output     = snapshot;
        fake_success_output_len = stringLength(snapshot);
        require(capturedeviceRemoveInstalledRules(&fixture.device), "unknown deletion could not be reconciled");
        require(recorded_call_count == 4U + present && capturedevicePendingRangeCount(&fixture.device) == 0,
                "reconciliation deleted an absent lane or missed a remaining lane");
        requireEqStr(recorded_calls[1].argv[8],
                     fixture.cidrs[present ? 1 : 0],
                     "reconciliation resumed cleanup at the wrong source range");
        requireEqStr(recorded_calls[1].argv[20],
                     present ? "70" : "72",
                     "reconciliation resumed cleanup at the wrong queue lane");
        for (size_t call = 0; call < recorded_call_count; ++call)
        {
            requireRuleProgress(&recorded_calls[call], &fixture.device);
        }
    }
}

static void testUnknownOpaqueAndInspectionFailure(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    fixture.states[0].opaque               = kCaptureRuleInstalled;
    fixture.states[kRuleTestQueues].opaque = kCaptureRuleOutcomeUnknown;
    fixture.states[2].queue                = kCaptureRuleInstalled;
    resetRecording(kFakeOutcomeTimeout, 0);
    require(! capturedeviceRemoveInstalledRules(&fixture.device), "failed reconciliation was accepted");
    require(recorded_call_count == 2 && fixture.states[kRuleTestQueues].opaque == kCaptureRuleOutcomeUnknown &&
                fixture.states[2].queue == kCaptureRuleOutcomeUnknown,
            "failed opaque inspection suppressed flow cleanup or erased uncertain ownership");

    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_success_output =
        "-A PREROUTING -m comment --comment WWCAP_OPAQUE_1234567890ABCDEF_0000000000000003 -j NFQUEUE\n";
    fake_success_output_len = stringLength(fake_success_output);
    require(capturedeviceRemoveInstalledRules(&fixture.device) && capturedevicePendingRangeCount(&fixture.device) == 0,
            "retry did not settle uncertain opaque and flow outcomes");
    require(recorded_call_count == 4, "retry did not inspect each rule kind and remove only present opaque rules");
    requireEqStr(recorded_calls[0].argv[6], "PREROUTING", "opaque reconciliation inspected the wrong chain");
    requireEqStr(recorded_calls[1].argv[8], fixture.cidrs[1], "opaque state mapped to the wrong source range");
    requireEqStr(recorded_calls[2].argv[8], fixture.cidrs[0], "opaque cleanup skipped the first source range");
    requireEqStr(recorded_calls[3].argv[6], "PREROUTING", "flow reconciliation inspected the wrong chain");
}

static void testRuleInstallationStopsWhenReaderFails(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    fake_reader_operational = false;
    require(! capturedeviceInstallRules(&fixture.device) && recorded_call_count == 0,
            "queue rules were installed without an operational reader");
    fake_reader_operational   = true;
    reader_failure_after_call = 1;
    require(! capturedeviceInstallRules(&fixture.device) && recorded_call_count == 1 &&
                fixture.states[0].queue == kCaptureRuleInstalled && fixture.states[1].queue == kCaptureRuleAbsent,
            "reader failure after mutation lost ownership or allowed later rule installation");
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceRemoveInstalledRules(&fixture.device) && recorded_call_count == 1,
            "failed reader's single committed rule was not rolled back");
}

static void testRuleCleanupBeforeQueueConstruction(void)
{
    capture_device_t device = {.capture_range_count = kRuleTestRanges};
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedevicePendingRangeCount(&device) == 0 && capturedeviceRemoveInstalledRules(&device),
            "early rollback did not recognize an unconstructed queue inventory");
    require(recorded_call_count == 0, "early rollback issued firewall commands without owned queue rules");
}

static void testSysctlUsesDirectArgvWithGroupedValues(void)
{
    static const char *const buffer_settings[] = {
        "net.core.rmem_max=", "net.core.wmem_max=", "net.ipv4.tcp_rmem=", "net.ipv4.tcp_wmem="};
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    capturedeviceApplySysctls(false);
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
        requireMutationOptions(call, "sysctl must use Capture's configured deadline, grace, and output cap");

        for (size_t setting = 0; setting < ARRAY_SIZE(buffer_settings); ++setting)
        {
            require(strncmp(call->argv[2], buffer_settings[setting], strlen(buffer_settings[setting])) != 0,
                    "Capture must not change global socket or TCP buffer settings");
        }

        if (strcmp(call->argv[2], "net.ipv4.ip_local_port_range=10000 65535") == 0)
        {
            found_multi_value = true;
        }
    }
    require(found_multi_value, "a multi-value sysctl setting must arrive as one argv element after -w");
    require(recorded_call_count == 10, "Capture must retain the ten remaining sysctl settings");
}

static void testSysctlNonzeroExitStaysBestEffort(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    capturedeviceApplySysctls(false);
    const size_t total_settings = recorded_call_count;

    // Fail the very first setting with an ordinary nonzero exit: the batch must
    // still attempt every remaining setting.
    resetRecording(kFakeOutcomeNonzeroExit, 0);
    capturedeviceApplySysctls(false);
    require(recorded_call_count == total_settings, "a normal sysctl failure must remain best-effort");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");
}

static void testSysctlTimeoutStopsTheRestOfTheBatch(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    capturedeviceApplySysctls(false);
    const size_t total_settings = recorded_call_count;
    require(total_settings > 2, "the sysctl batch must contain enough settings for this test");

    // Time out on the second setting: the first is attempted, the second hangs,
    // and nothing after it is retried.
    resetRecording(kFakeOutcomeTimeout, 1);
    capturedeviceApplySysctls(false);
    require(recorded_call_count == 2, "a sysctl timeout must stop the rest of the tuning batch");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");

    // A parent-side spawn failure stops the batch for the same reason.
    resetRecording(kFakeOutcomeSpawnFailure, 0);
    capturedeviceApplySysctls(false);
    require(recorded_call_count == 1, "a sysctl spawn failure must stop the rest of the tuning batch");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");

    resetRecording(kFakeOutcomeOutputTooLarge, 0);
    capturedeviceApplySysctls(false);
    require(recorded_call_count == 1, "a sysctl output-limit termination must stop the rest of the tuning batch");
    require(dropped_result_count == recorded_call_count, "every sysctl result must be dropped exactly once");
}

static void testSysctlSkipRunsNoCommands(void)
{
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    capturedeviceApplySysctls(true);
    require(recorded_call_count == 0, "skip-sysctl must suppress every sysctl command");
    require(dropped_result_count == 0, "skip-sysctl unexpectedly produced a command result");
}

static void testProtocolFilterUsesTheSamePredicateForEveryRule(void)
{
    capture_protocol_filter_t filter = {0};
    char                      bytecode[kCaptureLinuxProtocolFilterSize];
    captureLinuxBuildProtocolFilter(&filter, bytecode);
    require(bytecode[0] == '\0', "empty exclusions unnecessarily enabled a BPF match");
    captureProtocolFilterExclude(&filter, 0);
    captureProtocolFilterExclude(&filter, 6);
    captureLinuxBuildProtocolFilter(&filter, bytecode);

    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    const char *const operations[] = {"-I", "-D"};
    for (size_t i = 0; i < ARRAY_SIZE(operations); ++i)
    {
        require(capturedeviceRunIptablesQueueRule(operations[i], "192.0.2.0/24", 77, "WWCAP_TEST", bytecode) ==
                    kCapturedeviceCommandOk,
                "filtered NFQUEUE mutation failed");
    }
    require(recorded_call_count == 2, "filtered rules changed the number of mutations");
    for (size_t i = 0; i < recorded_call_count; ++i)
    {
        const recorded_call_t *call   = &recorded_calls[i];
        const size_t           offset = 22;
        require(call->argc == offset + 4, "protocol match has the wrong argument count");
        requireEqStr(call->argv[offset], "-m", "protocol matcher lost its module flag");
        requireEqStr(call->argv[offset + 1], "bpf", "protocol matcher uses the wrong module");
        requireEqStr(call->argv[offset + 2], "--bytecode", "protocol matcher lost its bytecode flag");
        requireEqStr(call->argv[offset + 3], bytecode, "insertion/deletion protocol predicates differ");
        requireMutationOptions(call, "filtered mutation lost its deadline");
    }
    requireNoShellInvocation();
}

static void openBytecodeSockets(const char *bytecode, int sockets[2])
{
    char               *cursor;
    const unsigned long count = strtoul(bytecode, &cursor, 10);
    struct sock_filter  instructions[64];
    require(count > 0 && count <= ARRAY_SIZE(instructions), "cBPF program exceeds xt_bpf's limit");
    for (unsigned long i = 0; i < count; ++i)
    {
        int consumed = 0;
        require(sscanf(cursor,
                       ",%hu %hhu %hhu %u%n",
                       &instructions[i].code,
                       &instructions[i].jt,
                       &instructions[i].jf,
                       &instructions[i].k,
                       &consumed) == 4 &&
                    consumed > 0,
                "invalid generated cBPF instruction");
        cursor += consumed;
    }
    require(*cursor == '\0', "trailing bytes in generated cBPF program");
    struct sock_fprog program = {.len = (unsigned short) count, .filter = instructions};
    require(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0, "unable to create cBPF test sockets");
    require(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) == 0,
            "the kernel rejected the generated cBPF program");
}

static void requireBytecodeResult(const int sockets[2], const uint8_t *packet, size_t length, bool expected,
                                  const char *message)
{
    require(send(sockets[0], packet, length, 0) == (ssize_t) length, "filter test send failed");
    uint8_t       received_byte;
    const ssize_t received = recv(sockets[1], &received_byte, sizeof(received_byte), MSG_DONTWAIT);
    require(expected ? received == 1 : received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK), message);
}

static void testProtocolFilterInTheKernel(void)
{
    /* Execute the actual generated cBPF on an unprivileged datagram socket.
     * No userspace interpreter or firewall privilege is needed to check all
     * protocol bytes, including bitmap word boundaries and an all-excluded set. */
    for (unsigned int scenario = 0; scenario < 4; ++scenario)
    {
        capture_protocol_filter_t filter = {0};
        for (unsigned int protocol = 0; protocol < kCaptureIpProtocolCount; ++protocol)
        {
            if (scenario == 0 || (scenario == 1 && protocol % 2 == 0) || (scenario == 2 && protocol % 31 == 0) ||
                (scenario == 3 && protocol == 255))
            {
                captureProtocolFilterExclude(&filter, (uint8_t) protocol);
            }
        }
        char bytecode[kCaptureLinuxProtocolFilterSize];
        captureLinuxBuildProtocolFilter(&filter, bytecode);
        int sockets[2];
        openBytecodeSockets(bytecode, sockets);
        for (unsigned int protocol = 0; protocol < kCaptureIpProtocolCount; ++protocol)
        {
            uint8_t packet[20] = {0x45};
            packet[9]          = (uint8_t) protocol;
            require(send(sockets[0], packet, sizeof(packet), 0) == sizeof(packet), "filter test send failed");
            const ssize_t received = recv(sockets[1], packet, sizeof(packet), MSG_DONTWAIT);
            if (captureProtocolFilterExcludes(&filter, (uint8_t) protocol))
            {
                require(received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
                        "the protocol filter admitted an excluded byte");
            }
            else
            {
                /* xt_bpf uses the positive result as a boolean; SO_ATTACH_FILTER
                 * additionally truncates admitted test datagrams to that value. */
                require(received == 1, "the protocol filter rejected a non-excluded byte");
            }
        }
        close(sockets[0]);
        close(sockets[1]);
    }
}

static void testProtocolFilterDoesNotInspectTcpPorts(void)
{
    capture_protocol_filter_t filter = {0};
    for (unsigned protocol = 0; protocol < kCaptureIpProtocolCount; ++protocol)
        if (protocol != IPPROTO_TCP)
            captureProtocolFilterExclude(&filter, (uint8_t) protocol);
    char bytecode[kCaptureLinuxProtocolFilterSize];
    captureLinuxBuildProtocolFilter(&filter, bytecode);
    int sockets[2];
    openBytecodeSockets(bytecode, sockets);

    /* Protocol selection must not require transport bytes or interpret fragments. */
    uint8_t packet[80] = {0x45};
    packet[9]          = IPPROTO_TCP;
    requireBytecodeResult(sockets, packet, 20, true, "TCP protocol predicate required transport bytes");
    const uint16_t ports[]     = {0, 1, 443, 40000, 65535};
    const uint16_t fragments[] = {0, 0x4000, 0x2000, 1};
    const uint8_t  ihls[]      = {5, 6, 15};
    for (size_t h = 0; h < ARRAY_SIZE(ihls); ++h)
        for (size_t p = 0; p < ARRAY_SIZE(ports); ++p)
            for (size_t f = 0; f < ARRAY_SIZE(fragments); ++f)
            {
                memset(packet, 0, sizeof(packet));
                const unsigned header_length = ihls[h] * 4U;
                const unsigned length        = header_length + 20U;
                packet[0]                    = (uint8_t) (0x40U | ihls[h]);
                packet[2]                    = (uint8_t) (length >> 8);
                packet[3]                    = (uint8_t) length;
                packet[6]                    = (uint8_t) (fragments[f] >> 8);
                packet[7]                    = (uint8_t) fragments[f];
                packet[9]                    = IPPROTO_TCP;
                packet[header_length]        = (uint8_t) (ports[p] >> 8);
                packet[header_length + 1]    = (uint8_t) ports[p];
                packet[header_length + 2]    = (uint8_t) (ports[ARRAY_SIZE(ports) - p - 1] >> 8);
                packet[header_length + 3]    = (uint8_t) ports[ARRAY_SIZE(ports) - p - 1];
                packet[header_length + 12]   = 0x50;
                requireBytecodeResult(sockets,
                                      packet,
                                      length,
                                      true,
                                      "TCP protocol predicate selected ports or rejected IP options/fragments");
                packet[9] = IPPROTO_UDP;
                requireBytecodeResult(
                    sockets, packet, length, false, "TCP protocol predicate admitted an excluded UDP packet");
            }
    close(sockets[0]);
    close(sockets[1]);
}

static void requireBpfMatch(const recorded_call_t *call, size_t offset, const char *bytecode, const char *message)
{
    require(call->argc >= offset + 4, message);
    requireEqStr(call->argv[offset], "-m", message);
    requireEqStr(call->argv[offset + 1], "bpf", message);
    requireEqStr(call->argv[offset + 2], "--bytecode", message);
    requireEqStr(call->argv[offset + 3], bytecode, message);
}

static void testProtocolAndSteeringUseSeparateMatchesOnEveryRule(void)
{
    capture_rule_fixture_t fixture;
    prepareRuleFixture(&fixture);
    capture_protocol_filter_t filter = {0};
    for (unsigned int protocol = 0; protocol < kCaptureIpProtocolCount; ++protocol)
    {
        if (protocol != 6)
            captureProtocolFilterExclude(&filter, (uint8_t) protocol);
    }
    captureLinuxBuildProtocolFilter(&filter, fixture.device.protocol_filter);

    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceInstallRules(&fixture.device), "protocol-filtered queue installation failed");
    require(recorded_call_count == 12, "protocol-filtered capture changed the owned rule inventory");
    for (size_t i = 0; i < 12; ++i)
    {
        const recorded_call_t *call = &recorded_calls[i];
        const size_t           lane = (i % 6) % kRuleTestQueues;
        char                   opaque_filter[kCaptureLinuxSteeringFilterSize];
        captureLinuxBuildOpaqueFilter(opaque_filter);
        requireEqStr(call->argv[6], "PREROUTING", "protocol-filtered capture rule left PREROUTING");
        requireBpfMatch(call, 22, fixture.device.protocol_filter, "capture rule lost its protocol predicate");
        requireBpfMatch(call,
                        26,
                        i < 6 ? fixture.queues[lane].steering_filter : opaque_filter,
                        "capture rule lost its steering predicate");
        require(call->argc == (i < 6 || lane == 0 ? 30 : 36), "capture rule has the wrong argument count");
    }
    require(capturedeviceRemoveInstalledRules(&fixture.device), "protocol-filtered cleanup failed");
    require(recorded_call_count == 24 && capturedevicePendingRangeCount(&fixture.device) == 0,
            "protocol-filtered cleanup did not retire every owned rule");
    for (size_t index = 0; index < 6; ++index)
    {
        requireMatchingDelete(&recorded_calls[11 - index], &recorded_calls[12 + index], 5);
        requireMatchingDelete(&recorded_calls[5 - index], &recorded_calls[18 + index], 5);
    }

    /* Startup rollback after a failed insertion deletes the same predicates. */
    resetRecording(kFakeOutcomeNonzeroExit, 2);
    require(! capturedeviceInstallRules(&fixture.device), "failed protocol-filtered insertion was accepted");
    require(recorded_call_count == 3, "failed protocol-filtered insertion continued");
    recorded_call_t inserted[2] = {recorded_calls[0], recorded_calls[1]};
    resetRecording(kFakeOutcomeSuccess, SIZE_MAX);
    require(capturedeviceRemoveInstalledRules(&fixture.device) && capturedevicePendingRangeCount(&fixture.device) == 0,
            "protocol-filtered rollback did not settle ownership");
    require(recorded_call_count == 2, "protocol-filtered rollback changed the installed inventory");
    requireMatchingDelete(&inserted[1], &recorded_calls[0], 5);
    requireMatchingDelete(&inserted[0], &recorded_calls[1], 5);
    requireNoShellInvocation();
}

int main(void)
{
    testCaseSet("capture_linux_command_test");
    testEarlyQueueInspectionUsesRawPrerouting();
    testInsertBuildsExactArgv();
    testDeleteBuildsExactArgv();
    testIptablesTimeoutIsDistinctFromNonzeroExit();
    testInputInspectionUsesLargeSnapshotCap();
    testInputInspectionRejectsEmptySnapshot();
    testQueueSelectionAvoidsReferencedNumbers();
    testQueueRangeSelection();
    testQueueSelectionInspectsBothHooks();
    testDeterministicModesInstallOnlyOwnedFlowRules();
    testMultiqueueRulesRetainExactLifecycle();
    testUnknownInsertReconciliation();
    testMultiqueuePartialInstallReconciliation();
    testOpaqueUnknownInstallCleanup();
    testOpaqueFailureStillRemovesFlowRules();
    testMultiqueueUnknownDeleteReconciliation();
    testUnknownOpaqueAndInspectionFailure();
    testRuleInstallationStopsWhenReaderFails();
    testRuleCleanupBeforeQueueConstruction();
    testSysctlUsesDirectArgvWithGroupedValues();
    testSysctlNonzeroExitStaysBestEffort();
    testSysctlTimeoutStopsTheRestOfTheBatch();
    testSysctlSkipRunsNoCommands();
    testProtocolFilterUsesTheSamePredicateForEveryRule();
    testProtocolFilterInTheKernel();
    testProtocolFilterDoesNotInspectTcpPorts();
    testProtocolAndSteeringUseSeparateMatchesOnEveryRule();

    printf("capture_linux_command_test: all tests passed\n");
    return 0;
}
