/**
 * @file wproc.c
 * @brief Platform-specific privilege helpers plus the deadline-aware command runner.
 */

#include "wproc.h"
#include "wplatform.h"
#include "wtime.h"

#if defined(OS_LINUX)
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef OS_WIN
#include <shellapi.h>

/**
 * @brief Checks whether the current process is running with administrative privileges.
 *
 * @return BOOL TRUE if running as admin, FALSE otherwise.
 */
bool isAdmin(void)
{
    BOOL   is_admin = FALSE;
    HANDLE h_token  = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token))
    {
        TOKEN_ELEVATION elevation;
        DWORD           dw_size;
        if (GetTokenInformation(h_token, TokenElevation, &elevation, sizeof(elevation), &dw_size))
        {
            is_admin = (BOOL) elevation.TokenIsElevated;
        }
    }

    if (h_token)
    {
        CloseHandle(h_token);
    }

    return is_admin;
}

/**
 * @brief Attempt to relaunch process with elevated privileges.
 *
 * @param app_name Application name (currently unused).
 * @param fail_msg Output message on failure (currently unused).
 * @return `true` when already elevated or relaunch succeeds.
 */
bool elevatePrivileges(const char *app_name, char *fail_msg)
{
    discard app_name;
    discard fail_msg;
    return false; // for now

    if (isAdmin())
    {
        return true;
    }
    char szPath[MAX_PATH];

    // Retrieve the full path of the current executable
    if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0)
    {
        // Handle error
        printError("Failed to get executable path. Error: %lu\n", GetLastError());
        return false;
    }

    if (GetModuleFileName(NULL, szPath, MAX_PATH))
    {
        SHELLEXECUTEINFO sei = {.cbSize = sizeof(sei),
                                .fMask  = 0,
                                .hwnd   = NULL,
                                .lpVerb = "runas", // Request elevation
                                .lpFile = szPath,  // Path to the current executable
                                .nShow  = SW_NORMAL};

        if (! ShellExecuteEx(&sei))
        {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED)
            {
                printError("User canceled the elevation prompt.\n");
            }
            else
            {
                printError("Failed to elevate privileges. Error: %lu\n", dwError);
            }
            return false;
        }
        else
        {
            // Successfully restarted with admin privileges
            ExitProcess(0); // Exit the current instance
        }
    }

    return true;
}

#else

/**
 * @brief Non-Windows fallback admin check.
 *
 * @return Always `true`.
 */
bool isAdmin(void)
{
    return true;
}

/**
 * @brief Non-Windows fallback privilege elevation.
 *
 * @param app_name Application name (unused).
 * @param fail_msg Output message (unused).
 * @return Always `true`.
 */
bool elevatePrivileges(const char *app_name, char *fail_msg)
{
    discard app_name;
    discard fail_msg;
    return true;
}

#endif

void procCommandResultDrop(proc_command_result_t *out)
{
    if (out == NULL)
    {
        return;
    }
    memoryFree(out->output);
    memoryZero(out, sizeof(*out));
}

#if defined(OS_LINUX)

enum
{
    // Initial stdout capture buffer, clamped down when the caller's cap is smaller.
    kProcCommandInitialCapacity = 4096,
    // Polling interval used while waiting for a child that has closed stdout, and
    // while observing the direct child during the post-SIGTERM grace period.
    kProcCommandChildPollUs = 2000,
    // Reads per drain pass. A producer that keeps the pipe continuously non-empty
    // never yields EAGAIN, so an unbounded pass can hold the loop past the
    // deadline. 32 * 4096 is two pipe buffers, so an ordinary burst still drains
    // in a single pass.
    kProcCommandMaxReadsPerPoll = 32
};

// Signal the child's own process group (pgid == child pid), tolerating a child
// that has already exited. The child, and best-effort the parent, set the
// child's process group to its own pid so a command is terminated together with
// every descendant. If the dedicated group was never established, fall back to
// the direct child. ESRCH means "already gone".
static void signalChildGroup(pid_t pid, int sig)
{
    if (pid <= 1)
    {
        return;
    }
    if (kill(-pid, sig) != 0 && errno == ESRCH)
    {
        (void) kill(pid, sig);
    }
}

// Translate a waitpid() status into the captured exit code.
static void recordChildStatus(proc_command_result_t *out, int status)
{
    if (WIFEXITED(status))
    {
        out->exit_code = WEXITSTATUS(status);
    }
    else if (WIFSIGNALED(status))
    {
        out->exit_code = 128 + WTERMSIG(status);
    }
}

// Blocking, EINTR-safe reap of the direct child. Records its exit/signal status.
static bool waitpidEintrSafe(pid_t pid, proc_command_result_t *out)
{
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno == EINTR)
        {
            continue;
        }
        return false;
    }
    recordChildStatus(out, status);
    return true;
}

// Remaining time until the monotonic deadline in whole milliseconds (rounded
// up), clamped to [0, INT_MAX] so it can be handed to poll().
static int remainingDeadlineMs(uint64_t deadline_us)
{
    const uint64_t now_us = (uint64_t) getHRTimeUs();
    if (now_us >= deadline_us)
    {
        return 0;
    }
    const uint64_t remaining_ms = (deadline_us - now_us + 999U) / 1000U;
    return remaining_ms > (uint64_t) INT_MAX ? INT_MAX : (int) remaining_ms;
}

// Bounded termination and reaping. Signals the child process group with SIGTERM,
// waits up to `grace_ms` for the direct child to exit, then escalates by
// signalling the whole process group with SIGKILL, and only then reaps the
// direct child. The group SIGKILL happens even when the direct child has already
// exited, because a SIGTERM-ignoring descendant can outlive its parent and would
// otherwise survive.
//
// The direct child is deliberately NOT reaped before the SIGKILL: during the
// grace period its exit is observed with waitid(WNOWAIT), which leaves it in a
// zombie/waitable state so its PID (and therefore the process-group id) stays
// reserved. Reaping first could free the PID and let the group/fallback signal
// reach an unrelated process that reused it. No path here returns with a known
// live or zombie direct child.
static void terminateAndReapChild(pid_t pid, uint32_t grace_ms, proc_command_result_t *out)
{
    signalChildGroup(pid, SIGTERM);

    const uint64_t grace_deadline_us = (uint64_t) getHRTimeUs() + ((uint64_t) grace_ms * 1000U);
    for (;;)
    {
        siginfo_t info;
        info.si_pid      = 0;
        const int waited = waitid(P_PID, (id_t) pid, &info, WEXITED | WNOHANG | WNOWAIT);
        if (waited == 0 && info.si_pid == pid)
        {
            break; // observed exit without reaping; PID stays reserved
        }
        if (waited < 0 && errno != EINTR)
        {
            break; // ECHILD: already gone (reaped elsewhere)
        }
        if ((uint64_t) getHRTimeUs() >= grace_deadline_us)
        {
            break; // still alive at the grace deadline
        }
        usleep(kProcCommandChildPollUs);
    }

    // Escalate to the whole group. Because the direct child has not been reaped,
    // its PID still reserves the process-group id, so this targets exactly our
    // descendants; an already-empty group is a harmless ESRCH.
    signalChildGroup(pid, SIGKILL);

    // Now reap the direct child. It is either an unreaped zombie observed above,
    // or guaranteed to exit promptly under the SIGKILL; either way this completes.
    (void) waitpidEintrSafe(pid, out);
}

// Grow the capture buffer to hold `additional` more bytes plus a NUL, never
// allocating beyond `max_output_bytes + 1`. The caller has already proven that
// `output_len + additional <= max_output_bytes`, so the clamped growth is always
// sufficient. Returns false only on allocation failure.
static bool ensureCaptureCapacity(proc_command_result_t *out, size_t *capacity, size_t additional,
                                  size_t max_output_bytes)
{
    const size_t required = out->output_len + additional + 1U;
    if (required <= *capacity)
    {
        return true;
    }
    const size_t hard_cap     = max_output_bytes + 1U;
    size_t       new_capacity = *capacity;
    while (new_capacity < required)
    {
        // Doubling would overflow past the hard cap; take the cap directly.
        if (new_capacity > hard_cap / 2U)
        {
            new_capacity = hard_cap;
            break;
        }
        new_capacity *= 2U;
    }
    char *new_output = memoryReAllocate(out->output, new_capacity);
    if (new_output == NULL)
    {
        return false;
    }
    out->output = new_output;
    *capacity   = new_capacity;
    return true;
}

// Move a pipe end above the standard descriptors. When the process was started
// with fd 0 and/or fd 1 closed, pipe() hands back {0,1}: the write end already
// is stdout, the child's dup2 is skipped, and FD_CLOEXEC survives to exec and
// closes the child's only stdout. Relocating both ends first guarantees the
// child's dup2 path always runs and keeps the read end from aliasing stdin.
static bool relocatePipeEndAboveStdio(int *fd)
{
    if (*fd > STDERR_FILENO)
    {
        return true;
    }
    const int relocated = fcntl(*fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    if (relocated < 0)
    {
        return false;
    }
    close(*fd);
    *fd = relocated;
    return true;
}

bool procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                             proc_command_result_t *out)
{
    assert(file != NULL && argv != NULL && options != NULL && out != NULL);

    memoryZero(out, sizeof(*out));
    out->exit_code = -1;

    // A zero cap would make every read an overflow; reject it rather than
    // pretending the drain loop is bounded. The SIZE_MAX clamp keeps the
    // `max_output_bytes + 1` capacity arithmetic overflow-free.
    if (options->max_output_bytes == 0)
    {
        out->spawn_failed = true;
        return false;
    }
    const size_t max_output_bytes = options->max_output_bytes == SIZE_MAX ? SIZE_MAX - 1U : options->max_output_bytes;

    const uint64_t deadline_us = (uint64_t) getHRTimeUs() + ((uint64_t) options->timeout_ms * 1000U);

    int output_pipe[2] = {-1, -1};
    if (pipe(output_pipe) != 0)
    {
        out->spawn_failed = true;
        return false;
    }
    // Keep both pipe ends close-on-exec. The child re-creates stdout via dup2,
    // which clears FD_CLOEXEC on the duplicate, so only the inherited copies
    // are closed at exec. That only holds while the write end is not already
    // stdout, which the relocation below guarantees.
    (void) fcntl(output_pipe[0], F_SETFD, FD_CLOEXEC);
    (void) fcntl(output_pipe[1], F_SETFD, FD_CLOEXEC);

    if (! relocatePipeEndAboveStdio(&output_pipe[0]) || ! relocatePipeEndAboveStdio(&output_pipe[1]))
    {
        close(output_pipe[0]);
        close(output_pipe[1]);
        out->spawn_failed = true;
        return false;
    }

    const long open_max = execCmdOpenMax();

    pid_t pid = fork();
    if (pid < 0)
    {
        close(output_pipe[0]);
        close(output_pipe[1]);
        out->spawn_failed = true;
        return false;
    }

    if (pid == 0)
    {
        // Own process group so a timeout can terminate the command and every
        // descendant together.
        setpgid(0, 0);
        close(output_pipe[0]);
        if (output_pipe[1] != STDOUT_FILENO)
        {
            if (dup2(output_pipe[1], STDOUT_FILENO) < 0)
            {
                _exit(127);
            }
            close(output_pipe[1]);
        }
        else
        {
            // Unreachable while the parent relocates both ends above the standard
            // descriptors, and kept correct so the child never depends on that.
            // There is no dup2 here to clear FD_CLOEXEC, so drop it explicitly or
            // exec closes the child's only stdout and the capture returns empty.
            const int fd_flags = fcntl(STDOUT_FILENO, F_GETFD, 0);
            if (fd_flags < 0 || fcntl(STDOUT_FILENO, F_SETFD, fd_flags & ~FD_CLOEXEC) < 0)
            {
                _exit(127);
            }
        }
        execCmdCloseInheritedFds(open_max);
        execvp(file, (char *const *) argv);
        _exit(127);
    }

    close(output_pipe[1]);
    output_pipe[1] = -1;
    // Best-effort duplicate of the child's setpgid to close the fork/exec race.
    // Harmless if the child already exec'd (EACCES) or exited (ESRCH).
    (void) setpgid(pid, pid);

    // Only the read end is nonblocking; the child's stdout stays blocking so a
    // large valid capture is never truncated with EAGAIN. A nonblocking read end
    // is what lets the drain loop stop on EAGAIN instead of blocking past the
    // deadline, so a failure to configure it is treated as a command failure.
    const int flags = fcntl(output_pipe[0], F_GETFL, 0);
    if (flags < 0 || fcntl(output_pipe[0], F_SETFL, flags | O_NONBLOCK) < 0)
    {
        out->spawn_failed = true;
        close(output_pipe[0]);
        output_pipe[0] = -1;
        terminateAndReapChild(pid, options->terminate_grace_ms, out);
        return false;
    }

    size_t capacity = kProcCommandInitialCapacity;
    if (capacity > max_output_bytes + 1U)
    {
        capacity = max_output_bytes + 1U;
    }
    out->output = memoryAllocate(capacity);
    if (out->output == NULL)
    {
        out->spawn_failed = true;
        close(output_pipe[0]);
        terminateAndReapChild(pid, options->terminate_grace_ms, out);
        return false;
    }
    out->output[0] = '\0';

    bool failed       = false;
    bool timed_out    = false;
    bool pipe_eof     = false;
    bool child_reaped = false;
    while (! pipe_eof || ! child_reaped)
    {
        const int remaining = remainingDeadlineMs(deadline_us);
        if (remaining == 0)
        {
            timed_out = true;
            break;
        }

        if (! pipe_eof)
        {
            struct pollfd pfd = {.fd = output_pipe[0], .events = POLLIN, .revents = 0};
            const int     pr  = poll(&pfd, 1, remaining);
            if (pr < 0)
            {
                if (errno == EINTR)
                {
                    continue; // recompute the remaining deadline and retry
                }
                out->spawn_failed = true;
                failed            = true;
                break;
            }
            if (pr == 0)
            {
                timed_out = true;
                break;
            }

            // Drain what is currently available after POLLIN/POLLHUP, bounded so
            // control returns to the deadline check. Stopping early loses nothing:
            // the read end is non-blocking and poll() reports POLLIN again
            // immediately while data is still pending.
            bool drain_error = false;
            for (int reads = 0; reads < kProcCommandMaxReadsPerPoll; ++reads)
            {
                char    buf[4096];
                ssize_t nread = read(output_pipe[0], buf, sizeof(buf));
                if (nread > 0)
                {
                    if ((size_t) nread > max_output_bytes - out->output_len)
                    {
                        out->output_too_large = true;
                        failed                = true;
                        drain_error           = true;
                        break;
                    }
                    if (! ensureCaptureCapacity(out, &capacity, (size_t) nread, max_output_bytes))
                    {
                        out->spawn_failed = true;
                        failed            = true;
                        drain_error       = true;
                        break;
                    }
                    memoryCopy(out->output + out->output_len, buf, (size_t) nread);
                    out->output_len += (size_t) nread;
                    out->output[out->output_len] = '\0';
                    continue;
                }
                if (nread == 0)
                {
                    pipe_eof = true;
                    break;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    break; // nothing more available right now; poll again
                }
                out->spawn_failed = true;
                failed            = true;
                drain_error       = true;
                break;
            }
            if (drain_error)
            {
                break;
            }
        }
        else
        {
            // The pipe has reached EOF but the child has not been reaped yet
            // (it may have closed stdout and kept running). Never block: poll the
            // child with WNOHANG under the same deadline, sleeping briefly between
            // checks so a stuck child still hits the timeout path.
            int         status = 0;
            const pid_t reaped = waitpid(pid, &status, WNOHANG);
            if (reaped == pid)
            {
                recordChildStatus(out, status);
                child_reaped = true;
            }
            else if (reaped < 0 && errno != EINTR)
            {
                child_reaped = true; // ECHILD: already reaped elsewhere
            }
            else if (reaped == 0)
            {
                usleep(kProcCommandChildPollUs);
            }
        }
    }

    close(output_pipe[0]);
    output_pipe[0] = -1;

    if (timed_out)
    {
        out->timed_out = true;
        failed         = true;
    }

    // The child is reaped on the clean path inside the loop; only terminate and
    // reap here when the deadline expired or an I/O error broke out early.
    if (failed || ! child_reaped)
    {
        terminateAndReapChild(pid, options->terminate_grace_ms, out);
        return false;
    }

    return out->exit_code == 0 && ! out->output_too_large && ! out->spawn_failed && ! out->timed_out;
}

#else

// No process-group guarantees outside Linux; report an honest spawn failure
// rather than pretending the supervised semantics exist. Current production
// callers of this API are Linux-only.
bool procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                             proc_command_result_t *out)
{
    assert(out != NULL);
    discard file;
    discard argv;
    discard options;

    memoryZero(out, sizeof(*out));
    out->exit_code    = -1;
    out->spawn_failed = true;
    return false;
}

#endif
