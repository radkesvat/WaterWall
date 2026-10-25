/*
 * Covers: wproc deadline; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Cases: testDirectArgvSuccessCapturesStdout, testClosedStdinAndStdoutStillCapturesStdout,
 * testSilentBlockingToolTimesOut, testClosedStdoutThenBlockStillTimesOut,
 * testPartialOutputThenBlockTimesOut, testSigtermIgnoringToolIsEscalatedToSigkill,
 * testProgressReleasesQuietChild, testRegisteredProgress, testExecCmdRegisteredProgress,
 * testProgressContinuesDuringFailureCleanup,
 * testShellDescendantLosesWholeProcessGroup, testShellCommandSucceedsWithoutTrailingNewline; the driver
 * lists the remaining cases
 * Checks: Assertion labels include: a clean direct-argv command must succeed; a clean command must record a
 * zero exit code; a clean command must have clean status flags; a clean command must hand back an owned
 * output buffer
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.wproc_deadline_unit
 */
// Focused coverage for the generic deadline-aware command supervisor in
// ww/base/wproc.c. Most cases use a short injected deadline plus a generous
// elapsed upper bound for loaded CI workers; the continuous-output regression
// repeats its timing check with cleanup grace and scheduling slack included.
// Every case ends by proving the process has no reapable children left.

#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum
{
    // The fake tools sleep far longer than any deadline used here, so a helper
    // that waited for them would blow straight past the upper bound.
    kFakeToolLongSleepSeconds   = 30,
    kShortDeadlineMs            = 300,
    kPartialDeadlineMs          = 400,
    kGenerousDeadlineMs         = 5000,
    kTerminateGraceMs           = 250,
    kTimeoutUpperBoundMs        = 8000,
    kDefaultMaxOutput           = 1024 * 1024,
    kContinuousOutputRuns       = 5,
    kContinuousOutputDeadlineMs = 100,
    kContinuousOutputSlackMs    = 1000
};

static uint64_t monotonicMs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t) ts.tv_sec * 1000U) + ((uint64_t) ts.tv_nsec / 1000000U);
}

// Create an executable temporary script whose body is @p body. The chosen path
// is written into @p path_out (must be at least 64 bytes). Aborts on failure.
static void writeTempTool(char *path_out, size_t path_len, const char *body)
{
    snprintf(path_out, path_len, "/tmp/waterwall-wproc-test-XXXXXX");
    int fd = mkstemp(path_out);
    require(fd >= 0, "could not create fake tool");
    const size_t len = strlen(body);
    require(write(fd, body, len) == (ssize_t) len, "could not write fake tool");
    require(close(fd) == 0, "could not close fake tool");
    require(chmod(path_out, 0700) == 0, "could not make fake tool executable");
}

// The supervisor must never leave a child behind: after it returns, this process
// must have no reapable children left.
static void requireNoChildren(const char *message)
{
    errno = 0;
    require(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD, message);
}

static proc_command_options_t makeOptions(uint32_t timeout_ms, size_t max_output_bytes)
{
    const proc_command_options_t options = {
        .timeout_ms = timeout_ms, .terminate_grace_ms = kTerminateGraceMs, .max_output_bytes = max_output_bytes};
    return options;
}

typedef struct command_progress_probe_s
{
    proc_command_result_t *result;
    pid_t                  parent_pid;
    unsigned int           calls;
    unsigned int           cleanup_calls;
    int                    release_fd;
} command_progress_probe_t;

static void recordCommandProgress(void *context)
{
    command_progress_probe_t *probe = context;
    require(getpid() == probe->parent_pid, "progress must run only in the calling parent");
    ++probe->calls;
    if (probe->result->timed_out || probe->result->output_too_large)
    {
        ++probe->cleanup_calls;
    }
    if (probe->release_fd >= 0 && probe->calls == 6)
    {
        require(write(probe->release_fd, "x", 1) == 1, "progress could not release the quiet child");
    }
}

static void testProgressReleasesQuietChild(void)
{
    // The child cannot exit until progress has run repeatedly. Exercise both
    // stdout polling and the waitpid path after EOF, without timing thresholds.
    for (unsigned int close_stdout = 0; close_stdout < 2; ++close_stdout)
    {
        char release_path[] = "/tmp/waterwall-wproc-release-XXXXXX";
        int  release_fd     = mkstemp(release_path);
        require(release_fd >= 0, "could not create the child release file");
        char tool[64];
        writeTempTool(tool,
                      sizeof(tool),
                      "#!/bin/sh\nif [ \"$2\" = closed ]; then exec 1>&-; fi\n"
                      "while [ ! -s \"$1\" ]; do sleep 0.01; done\n");

        const char *const        argv[]  = {tool, release_path, close_stdout ? "closed" : "open", NULL};
        proc_command_options_t   options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
        proc_command_result_t    result;
        command_progress_probe_t probe = {.result = &result, .parent_pid = getpid(), .release_fd = release_fd};
        options.progress               = recordCommandProgress;
        options.progress_context       = &probe;
        require(procRunArgvWithDeadline(tool, argv, &options, &result),
                "recurring progress must release a quiet child before the actual deadline");
        require(probe.calls >= 6, "a quiet child needs repeated progress calls");
        require(! result.timed_out && probe.cleanup_calls == 0,
                "a progress poll slice must not be treated as the command deadline");
        procCommandResultDrop(&result);
        requireNoChildren("the progress-released command left an unreaped child");
        require(close(release_fd) == 0, "could not close the child release file");
        require(unlink(release_path) == 0, "could not remove the child release file");
        require(unlink(tool) == 0, "could not remove fake tool");
    }
}

static void testRegisteredProgress(void)
{
    char      release_path[] = "/tmp/waterwall-wproc-registered-XXXXXX";
    const int release_fd     = mkstemp(release_path);
    require(release_fd >= 0, "could not create registered-progress release file");
    const char *const argv[] = {"sh", "-c", "while [ ! -s \"$1\" ]; do sleep 0.01; done", "sh", release_path, NULL};
    proc_command_options_t   options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t    result;
    command_progress_probe_t first              = {.result = &result, .parent_pid = getpid(), .release_fd = -1};
    command_progress_probe_t second             = {.result = &result, .parent_pid = getpid(), .release_fd = release_fd};
    proc_command_progress_t  first_registration = {.callback = recordCommandProgress, .context = &first};
    proc_command_progress_t  second_registration = {.callback = recordCommandProgress, .context = &second};
    procCommandProgressRegister(&first_registration);
    procCommandProgressRegister(&second_registration);
    require(procRunArgvWithDeadline("/bin/sh", argv, &options, &result),
            "registered resources must make progress during commands with ordinary options");
    require(first.calls >= 6 && second.calls == first.calls && ! result.timed_out,
            "quiet command did not service both registered resources on each progress slice");
    procCommandResultDrop(&result);

    // Remove an interior registration while retaining the head, and combine
    // registered service with an explicit per-command callback.
    const unsigned first_calls  = first.calls;
    unsigned       second_calls = second.calls;
    procCommandProgressUnregister(&first_registration);
    command_progress_probe_t per_command = {.result = &result, .parent_pid = getpid(), .release_fd = -1};
    options.progress                     = recordCommandProgress;
    options.progress_context             = &per_command;
    const char *const quick[]            = {"/bin/true", NULL};
    require(procRunArgvWithDeadline(quick[0], quick, &options, &result), "command with mixed progress failed");
    require(first.calls == first_calls && second.calls > second_calls && per_command.calls > 0,
            "unregister lost another resource or suppressed explicit progress");
    procCommandResultDrop(&result);

    second_calls = second.calls;
    procCommandProgressUnregister(&second_registration);
    options.progress         = NULL;
    options.progress_context = NULL;
    require(procRunArgvWithDeadline(quick[0], quick, &options, &result), "ordinary command after unregister failed");
    require(first.calls == first_calls && second.calls == second_calls,
            "unregistered resources remained reachable by later commands");
    procCommandResultDrop(&result);
    requireNoChildren("registered-progress command left an unreaped child");
    require(close(release_fd) == 0 && unlink(release_path) == 0, "could not remove registered-progress release file");
}

static void testExecCmdRegisteredProgress(void)
{
    for (unsigned close_stdout = 0; close_stdout < 2; ++close_stdout)
    {
        char      release_path[] = "/tmp/waterwall-exec-progress-XXXXXX";
        const int release_fd     = mkstemp(release_path);
        require(release_fd >= 0, "could not create shell-command release file");
        proc_command_result_t    observation = {0};
        command_progress_probe_t first       = {.result = &observation, .parent_pid = getpid(), .release_fd = -1};
        command_progress_probe_t second = {.result = &observation, .parent_pid = getpid(), .release_fd = release_fd};
        proc_command_progress_t  first_registration  = {.callback = recordCommandProgress, .context = &first};
        proc_command_progress_t  second_registration = {.callback = recordCommandProgress, .context = &second};
        procCommandProgressRegister(&first_registration);
        procCommandProgressRegister(&second_registration);
        // Bound the fixture's own wait so a broken progress path fails with
        // status 99; execCmd itself keeps its unlimited script semantics.
        char command[512];
        snprintf(command,
                 sizeof(command),
                 "%s i=0; while [ ! -s '%s' ] && [ \"$i\" -lt 100 ]; do i=$((i+1)); sleep 0.01; done; "
                 "[ -s '%s' ] || exit 99; %s exit 7",
                 close_stdout ? "exec 1>&-;" : "",
                 release_path,
                 release_path,
                 close_stdout ? "" : "printf 'registered';");
        const cmd_result_t result = execCmd(command);
        require(result.exit_code == 7 && strcmp(result.output, close_stdout ? "" : "registered") == 0,
                "shell-command progress lost script exit status/output or did not release its wait");
        require(first.calls >= 6 && first.calls == second.calls,
                "quiet shell command did not repeatedly service every registered resource");
        procCommandProgressUnregister(&first_registration);
        procCommandProgressUnregister(&second_registration);
        requireNoChildren("shell-command progress left an unreaped child");
        require(close(release_fd) == 0 && unlink(release_path) == 0, "could not remove shell-command release file");
    }
}

static void testProgressContinuesDuringFailureCleanup(bool registered)
{
    for (unsigned int overflow = 0; overflow < 2; ++overflow)
    {
        char tool[64];
        // Ignoring TERM survives exec. The direct child must stay alive for the
        // whole grace period after either timeout or an output-limit failure.
        writeTempTool(tool, sizeof(tool), "#!/bin/sh\ntrap '' TERM\nprintf 'ready for cleanup'\nexec sleep 30\n");
        const char *const        argv[]  = {tool, NULL};
        proc_command_options_t   options = makeOptions(kShortDeadlineMs, overflow ? 8 : kDefaultMaxOutput);
        proc_command_result_t    result;
        command_progress_probe_t probe  = {.result = &result, .parent_pid = getpid(), .release_fd = -1};
        command_progress_probe_t other  = {.result = &result, .parent_pid = getpid(), .release_fd = -1};
        proc_command_progress_t  first  = {.callback = recordCommandProgress, .context = &probe};
        proc_command_progress_t  second = {.callback = recordCommandProgress, .context = &other};
        if (registered)
        {
            procCommandProgressRegister(&first);
            procCommandProgressRegister(&second);
        }
        else
        {
            options.progress         = recordCommandProgress;
            options.progress_context = &probe;
        }
        const uint64_t start = monotonicMs();
        require(! procRunArgvWithDeadline(tool, argv, &options, &result),
                "a blocked or oversized command must fail while providing progress");
        const uint64_t elapsed = monotonicMs() - start;
        require(result.timed_out == ! overflow && result.output_too_large == (bool) overflow,
                "progress must preserve the original command failure");
        require(result.exit_code == 128 + SIGKILL, "the TERM-ignoring child must survive until escalation");
        require(probe.cleanup_calls >= 3, "progress must recur throughout termination grace after failure");
        if (registered)
        {
            require(other.cleanup_calls == probe.cleanup_calls,
                    "failure cleanup stopped servicing one registered resource");
            procCommandProgressUnregister(&second);
            procCommandProgressUnregister(&first);
        }
        require(elapsed < kTimeoutUpperBoundMs, "progress must preserve the bounded command deadline");
        procCommandResultDrop(&result);
        requireNoChildren("failure cleanup with progress left an unreaped child");
        require(unlink(tool) == 0, "could not remove fake tool");
    }
}

static void testDirectArgvSuccessCapturesStdout(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nprintf 'hello %s\\n' \"$1\"\nexit 0\n");

    const char *const      argv[]  = {tool, "world", NULL};
    proc_command_options_t options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    require(procRunArgvWithDeadline(tool, argv, &options, &result), "a clean direct-argv command must succeed");
    require(result.exit_code == 0, "a clean command must record a zero exit code");
    require(! result.timed_out && ! result.spawn_failed && ! result.output_too_large,
            "a clean command must have clean status flags");
    require(result.output != NULL, "a clean command must hand back an owned output buffer");
    require(strcmp(result.output, "hello world\n") == 0, "the captured stdout does not match the emitted bytes");
    require(result.output_len == strlen("hello world\n"), "output_len must exclude the terminating NUL");
    procCommandResultDrop(&result);
    requireNoChildren("a successful command left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static int saveStandardDescriptor(int fd, int open_flags, int minimum)
{
    int saved = fcntl(fd, F_DUPFD_CLOEXEC, minimum);
    if (saved >= 0)
    {
        return saved;
    }

    const int fallback = open("/dev/null", open_flags | O_CLOEXEC);
    if (fallback < 0)
    {
        return -1;
    }
    saved = fcntl(fallback, F_DUPFD_CLOEXEC, minimum);
    close(fallback);
    return saved;
}

// Regression: started with fds 0 and 1 closed, pipe() returns {0,1} and the pipe
// write end already is stdout. The child's dup2 is then skipped, so nothing
// clears FD_CLOEXEC and exec used to close the child's only stdout, yielding a
// silent empty capture with a clean exit code.
static void testClosedStdinAndStdoutStillCapturesStdout(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nprintf 'captured\\n'\nexit 0\n");

    // Save the real descriptors before closing them. If the harness was itself
    // started with one closed, use a duplicate of /dev/null so the restore below
    // still produces a valid descriptor above the standard-descriptor range.
    const int saved_stdin  = saveStandardDescriptor(STDIN_FILENO, O_RDONLY, 20);
    const int saved_stdout = saveStandardDescriptor(STDOUT_FILENO, O_WRONLY, 21);
    require(saved_stdin >= 0 && saved_stdout >= 0, "could not save the standard descriptors");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);

    const char *const      argv[]  = {tool, NULL};
    proc_command_options_t options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    const bool             ok = procRunArgvWithDeadline(tool, argv, &options, &result);

    // Restore before asserting: require() on failure prints and exits, and every
    // later test needs real standard descriptors back.
    const bool stdin_restored  = dup2(saved_stdin, STDIN_FILENO) == STDIN_FILENO;
    const bool stdout_restored = dup2(saved_stdout, STDOUT_FILENO) == STDOUT_FILENO;
    close(saved_stdin);
    close(saved_stdout);
    require(stdin_restored && stdout_restored, "could not restore the standard descriptors");

    require(ok, "a command started with fds 0 and 1 closed must still succeed");
    require(result.exit_code == 0, "the command must record a zero exit code");
    require(! result.timed_out && ! result.spawn_failed && ! result.output_too_large,
            "a clean command must have clean status flags");
    require(result.output != NULL && strcmp(result.output, "captured\n") == 0,
            "stdout must be captured even when the pipe write end lands on fd 1");
    procCommandResultDrop(&result);
    requireNoChildren("the closed-stdio command left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testSilentBlockingToolTimesOut(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec sleep 30\n");

    const char *const      argv[]  = {tool, NULL};
    proc_command_options_t options = makeOptions(kShortDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    const uint64_t         start = monotonicMs();
    require(! procRunArgvWithDeadline(tool, argv, &options, &result), "a silent blocking tool must fail");
    const uint64_t elapsed = monotonicMs() - start;
    require(result.timed_out, "a silent blocking tool must be reported as timed out");
    require(result.output_len == 0, "a silent blocking tool must produce no captured output");
    require(elapsed < kTimeoutUpperBoundMs, "the runner must not wait for the fake tool's long sleep");
    procCommandResultDrop(&result);
    requireNoChildren("a timed-out command left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testClosedStdoutThenBlockStillTimesOut(void)
{
    char tool[64];
    // Close stdout (the pipe reaches EOF immediately) but keep running. EOF must
    // not turn the final wait into an unbounded blocking waitpid().
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec 1>&-\nexec sleep 30\n");

    const char *const      argv[]  = {tool, NULL};
    proc_command_options_t options = makeOptions(kShortDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    const uint64_t         start = monotonicMs();
    require(! procRunArgvWithDeadline(tool, argv, &options, &result),
            "a tool that closes stdout then blocks must still time out");
    const uint64_t elapsed = monotonicMs() - start;
    require(result.timed_out, "closing stdout early must not turn a hang into success");
    require(elapsed < kTimeoutUpperBoundMs, "EOF must not trigger an unbounded blocking wait");
    procCommandResultDrop(&result);
    requireNoChildren("a stdout-closed timeout left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testPartialOutputThenBlockTimesOut(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nprintf 'partial output'\nexec sleep 30\n");

    const char *const      argv[]  = {tool, NULL};
    proc_command_options_t options = makeOptions(kPartialDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    const uint64_t         start = monotonicMs();
    require(! procRunArgvWithDeadline(tool, argv, &options, &result),
            "a tool that blocks after partial output must fail");
    const uint64_t elapsed = monotonicMs() - start;
    require(result.timed_out, "partial-then-block must be reported as timed out");
    require(elapsed < kTimeoutUpperBoundMs, "partial output must not extend the deadline");
    // A timeout is never success regardless of what partial bytes were captured.
    require(result.exit_code != 0, "partial-then-block must not report a successful exit");
    procCommandResultDrop(&result);
    requireNoChildren("a partial-output timeout left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testSigtermIgnoringToolIsEscalatedToSigkill(void)
{
    char tool[64];
    // Ignore SIGTERM and keep looping; only SIGKILL can stop this process group.
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\ntrap '' TERM\nwhile : ; do sleep 1 ; done\n");

    const char *const      argv[]  = {tool, NULL};
    proc_command_options_t options = makeOptions(kShortDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    const uint64_t         start = monotonicMs();
    require(! procRunArgvWithDeadline(tool, argv, &options, &result), "a SIGTERM-ignoring tool must still fail");
    const uint64_t elapsed = monotonicMs() - start;
    require(result.timed_out, "a SIGTERM-ignoring tool must be reported as timed out");
    require(elapsed < kTimeoutUpperBoundMs, "SIGKILL escalation must keep the total wait bounded");
    procCommandResultDrop(&result);
    requireNoChildren("SIGKILL escalation left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

// The generic API is direct argv, but the socket-manager shell wrapper runs
// /bin/sh explicitly through argv. This case proves the supervisor handles that
// exact descendant topology: the whole process group must go, not just the
// direct child.
static void testShellDescendantLosesWholeProcessGroup(void)
{
    char pidfile[64];
    snprintf(pidfile, sizeof(pidfile), "/tmp/waterwall-wproc-pgrp-XXXXXX");
    int pfd = mkstemp(pidfile);
    require(pfd >= 0, "could not create pid file");
    require(close(pfd) == 0, "could not close pid file");

    // Background a SIGTERM-ignoring descendant that records its pid, then block
    // the shell. The direct child (the foreground sleep) dies on the group
    // SIGTERM, but the descendant only dies when the group is escalated to
    // SIGKILL. Reaping the direct child alone must not be treated as enough.
    char command[256];
    snprintf(command,
             sizeof(command),
             "( trap '' TERM; while : ; do sleep 1 ; done ) & echo $! > '%s'; exec sleep 30",
             pidfile);

    const char *const      argv[]  = {"sh", "-c", command, NULL};
    proc_command_options_t options = makeOptions(kPartialDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    require(! procRunArgvWithDeadline("/bin/sh", argv, &options, &result), "a blocking shell command must fail");
    require(result.timed_out, "a blocking shell command must be reported as timed out");
    procCommandResultDrop(&result);
    requireNoChildren("a shell command timeout left an unreaped direct child");

    FILE *f = fopen(pidfile, "r");
    require(f != NULL, "could not open descendant pid file");
    long      descendant = 0;
    const int scanned    = fscanf(f, "%ld", &descendant);
    require(fclose(f) == 0, "could not close descendant pid file");
    require(scanned == 1 && descendant > 1, "could not read a valid descendant pid");

    bool gone = false;
    for (int i = 0; i < 300; ++i)
    {
        if (kill((pid_t) descendant, 0) != 0 && errno == ESRCH)
        {
            gone = true;
            break;
        }
        usleep(10000);
    }
    require(gone, "the shell descendant survived the process-group timeout");
    require(unlink(pidfile) == 0, "could not remove descendant pid file");
}

static void testShellCommandSucceedsWithoutTrailingNewline(void)
{
    // The generic runner has no opinion about trailing newlines: a clean zero
    // exit succeeds regardless of how the last captured line ends.
    const char *const      argv[]  = {"sh", "-c", "printf 'no newline'", NULL};
    proc_command_options_t options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    require(procRunArgvWithDeadline("/bin/sh", argv, &options, &result),
            "a clean zero-exit shell command must succeed without a trailing newline");
    require(result.exit_code == 0, "the shell command must record a zero exit code");
    require(strcmp(result.output, "no newline") == 0, "the captured stdout does not match the emitted bytes");
    require(! result.timed_out && ! result.spawn_failed, "a clean shell command must not report a timeout or failure");
    procCommandResultDrop(&result);
    requireNoChildren("a clean shell command left an unreaped child");
}

static void testNonzeroExitIsNotTimeoutOrSpawnFailure(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nprintf 'partial\\n'\nexit 3\n");

    const char *const      argv[]  = {tool, NULL};
    proc_command_options_t options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    require(! procRunArgvWithDeadline(tool, argv, &options, &result), "a nonzero exit must fail the command");
    require(! result.timed_out, "a nonzero exit must not be reported as a timeout");
    require(! result.spawn_failed, "a nonzero exit is not a spawn failure");
    require(! result.output_too_large, "a nonzero exit is not an output-size failure");
    require(result.exit_code == 3, "the child's nonzero exit code must be recorded verbatim");
    require(strcmp(result.output, "partial\n") == 0, "output emitted before a nonzero exit must still be captured");
    procCommandResultDrop(&result);
    requireNoChildren("a nonzero-exit command left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testExecFailureIsReportedAsExit127(void)
{
    // An execvp() failure exits the child with status 127; it is a command
    // failure, not a parent-side spawn failure.
    const char *const      argv[]  = {"waterwall-no-such-tool", NULL};
    proc_command_options_t options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    require(! procRunArgvWithDeadline("waterwall-no-such-tool", argv, &options, &result),
            "a missing executable must fail the command");
    require(result.exit_code == 127, "a failed execvp must surface as child exit status 127");
    require(! result.spawn_failed, "a failed execvp is not a parent-side spawn failure");
    require(! result.timed_out, "a failed execvp is not a timeout");
    procCommandResultDrop(&result);
    requireNoChildren("a failed execvp left an unreaped child");
}

static void testOutputSizeLimitFailsAndTerminatesProducer(void)
{
    char tool[64];
    // yes(1) produces output far beyond any cap configured here.
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec yes WWpadding\n");

    const size_t           max_output = 4096;
    const char *const      argv[]     = {tool, NULL};
    proc_command_options_t options    = makeOptions(kGenerousDeadlineMs, max_output);
    proc_command_result_t  result;
    const uint64_t         start = monotonicMs();
    require(! procRunArgvWithDeadline(tool, argv, &options, &result), "oversized output must fail the command");
    const uint64_t elapsed = monotonicMs() - start;
    require(result.output_too_large, "oversized output must set the output_too_large flag");
    require(! result.timed_out, "oversized output is a size failure, not a timeout");
    require(! result.spawn_failed, "oversized output is not a spawn failure");
    require(result.output_len <= max_output, "captured output must stay within the configured cap");
    require(elapsed < kTimeoutUpperBoundMs, "the producer must be terminated promptly, not waited out");
    procCommandResultDrop(&result);
    requireNoChildren("an oversized-output command left an unreaped producer");
    require(unlink(tool) == 0, "could not remove fake tool");
}

// Regression: a producer that keeps the pipe continuously non-empty may not yield
// EAGAIN, so an unbounded drain pass can run far past the deadline. A single
// unfixed run can still finish promptly when it happens to yield, so repeat the
// command and constrain the worst case. The bounded pass returns to the deadline
// check after at most 128 KiB on every run.
static void testContinuousOutputStillHonoursTheDeadline(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec yes WWpadding\n");

    // A cap far larger than anything the deadline allows reading: the run must
    // end on the deadline, not on the cap.
    const size_t           huge_cap    = (size_t) 1024 * 1024 * 1024;
    const char *const      argv[]      = {tool, NULL};
    proc_command_options_t options     = makeOptions(kContinuousOutputDeadlineMs, huge_cap);
    uint64_t               max_elapsed = 0;

    for (int run = 0; run < kContinuousOutputRuns; ++run)
    {
        proc_command_result_t result;
        const uint64_t        start = monotonicMs();
        require(! procRunArgvWithDeadline(tool, argv, &options, &result), "a continuous producer must not succeed");
        const uint64_t elapsed = monotonicMs() - start;
        if (elapsed > max_elapsed)
        {
            max_elapsed = elapsed;
        }

        require(result.timed_out, "a continuous producer under a large cap must be reported as timed out");
        require(! result.output_too_large, "the run must end on the deadline, not on the output cap");
        procCommandResultDrop(&result);
        requireNoChildren("the continuous-producer command left an unreaped child");
    }

    require(unlink(tool) == 0, "could not remove fake tool");
    // The measured call includes post-deadline termination/reaping and scheduler delays.
    const uint64_t elapsed_limit =
        (uint64_t) options.timeout_ms + options.terminate_grace_ms + kContinuousOutputSlackMs;
    if (max_elapsed >= elapsed_limit)
    {
        fprintf(stderr,
                "FAIL: the continuous-output command exceeded its elapsed-time budget (max=%llu ms, limit=%llu ms)\n",
                (unsigned long long) max_elapsed,
                (unsigned long long) elapsed_limit);
        exit(1);
    }
}

static void testZeroOutputCapIsRejected(void)
{
    const char *const      argv[]  = {"/bin/true", NULL};
    proc_command_options_t options = makeOptions(kGenerousDeadlineMs, 0);
    proc_command_result_t  result;
    require(! procRunArgvWithDeadline("/bin/true", argv, &options, &result), "a zero output cap must be rejected");
    require(result.spawn_failed, "a zero output cap must be reported as a spawn failure");
    require(result.exit_code == -1, "a rejected command must leave the exit code unset");
    procCommandResultDrop(&result);
    requireNoChildren("a rejected command must never fork");
}

static void testDropIsSafeAndIdempotent(void)
{
    // After success.
    const char *const      ok_argv[] = {"sh", "-c", "printf 'x\\n'", NULL};
    proc_command_options_t options   = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    require(procRunArgvWithDeadline("/bin/sh", ok_argv, &options, &result), "the setup command must succeed");
    procCommandResultDrop(&result);
    require(result.output == NULL && result.output_len == 0, "drop must release and zero the captured output");
    require(result.exit_code == 0 && ! result.timed_out && ! result.spawn_failed && ! result.output_too_large,
            "drop must zero the entire result");
    procCommandResultDrop(&result);
    require(result.output == NULL, "a repeated drop must remain safe");

    // After a timeout.
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec sleep 30\n");
    const char *const      slow_argv[] = {tool, NULL};
    proc_command_options_t short_opts  = makeOptions(kShortDeadlineMs, kDefaultMaxOutput);
    require(! procRunArgvWithDeadline(tool, slow_argv, &short_opts, &result), "the blocking tool must time out");
    require(result.timed_out, "the blocking tool must be marked timed out");
    procCommandResultDrop(&result);
    require(! result.timed_out && result.output == NULL, "drop must clear every flag, including timed_out");
    procCommandResultDrop(&result);
    require(result.output == NULL, "a repeated drop after a timeout must remain safe");

    // After partial initialization and on NULL.
    proc_command_result_t partial;
    memset(&partial, 0, sizeof(partial));
    procCommandResultDrop(&partial);
    require(partial.output == NULL && partial.exit_code == 0, "drop must accept a zero-initialized result");
    procCommandResultDrop(NULL);

    requireNoChildren("the idempotent-drop test left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

int main(void)
{
    testCaseSet("wproc_deadline_test");
    testDirectArgvSuccessCapturesStdout();
    testProgressReleasesQuietChild();
    testRegisteredProgress();
    testExecCmdRegisteredProgress();
    testProgressContinuesDuringFailureCleanup(false);
    testProgressContinuesDuringFailureCleanup(true);
    testClosedStdinAndStdoutStillCapturesStdout();
    testSilentBlockingToolTimesOut();
    testClosedStdoutThenBlockStillTimesOut();
    testPartialOutputThenBlockTimesOut();
    testSigtermIgnoringToolIsEscalatedToSigkill();
    testShellDescendantLosesWholeProcessGroup();
    testShellCommandSucceedsWithoutTrailingNewline();
    testNonzeroExitIsNotTimeoutOrSpawnFailure();
    testExecFailureIsReportedAsExit127();
    testOutputSizeLimitFailsAndTerminatesProducer();
    testContinuousOutputStillHonoursTheDeadline();
    testZeroOutputCapIsRejected();
    testDropIsSafeAndIdempotent();

    printf("wproc_deadline_test: all tests passed\n");
    return 0;
}
