// Focused coverage for the generic deadline-aware command supervisor in
// ww/base/wproc.c. Most cases use a short injected deadline plus a generous
// elapsed upper bound so a loaded CI worker cannot flake; the continuous-output
// regression repeats its timing check to distinguish the bounded drain pass.
// Every case ends by proving the process has no reapable children left.

#include "wwapi.h"

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
    kContinuousOutputSlackMs    = 100
};

static bool fail_next_allocation = false;

void *__real_memoryAllocate(size_t size);
void *__wrap_memoryAllocate(size_t size);

void *__wrap_memoryAllocate(size_t size)
{
    if (fail_next_allocation)
    {
        fail_next_allocation = false;
        return NULL;
    }
    return __real_memoryAllocate(size);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

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
    const uint64_t elapsed_limit = (uint64_t) kContinuousOutputDeadlineMs + kContinuousOutputSlackMs;
    if (max_elapsed >= elapsed_limit)
    {
        fprintf(stderr,
                "FAIL: the drain loop ran far past the deadline (max=%llu ms, limit=%llu ms)\n",
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

static void testAllocationFailureAfterForkReapsChild(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec sleep 30\n");

    const char *const      argv[]  = {tool, NULL};
    proc_command_options_t options = makeOptions(kGenerousDeadlineMs, kDefaultMaxOutput);
    proc_command_result_t  result;
    const uint64_t         start = monotonicMs();
    fail_next_allocation         = true;
    require(! procRunArgvWithDeadline(tool, argv, &options, &result),
            "the command must fail when the capture allocation fails");
    const uint64_t elapsed = monotonicMs() - start;
    require(! fail_next_allocation, "the injected allocation failure was never consumed");
    require(result.spawn_failed, "an allocation failure must be reported as a spawn failure");
    require(! result.timed_out, "an allocation failure is not a timeout");
    require(elapsed < kTimeoutUpperBoundMs, "an allocation failure must terminate the child, not wait for it");
    procCommandResultDrop(&result);
    requireNoChildren("an allocation failure left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
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
    testDirectArgvSuccessCapturesStdout();
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
    testAllocationFailureAfterForkReapsChild();
    testDropIsSafeAndIdempotent();

    printf("wproc_deadline_test: all tests passed\n");
    return 0;
}
