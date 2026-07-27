#pragma once

/*
 * Signal manager API for shutdown handlers and process termination flow.
 */

#include "wlibc.h"
#include "worker.h"

typedef void (*SignalHandler)(void *userdata, int signum);

typedef struct
{
    SignalHandler handle;
    void         *userdata;
} signal_handler_t;

enum
{
    kMaxSigHandles = 500
};

/**
 * @brief Explicit process shutdown phase.
 *
 * The phase is the single source of truth for shutdown progress.
 * GSTATE.application_stopping_flag is a published compatibility flag derived
 * from it: it stays false while shutdown is merely kProgramShutdownRequested so
 * the control wakeup can still be delivered and the requesting thread can
 * unwind, and worker 0 sets it true when it enters kProgramShutdownStopping.
 *
 * RUNNING -> REQUESTED   requestProgramShutdown() / OS signal / console event
 * REQUESTED -> STOPPING  worker 0 only, exactly once
 * STOPPING -> FINALIZING workers stopped and joined
 * FINALIZING -> exit()   global resources destroyed
 */
typedef enum program_shutdown_phase_e
{
    kProgramShutdownRunning = 0,
    kProgramShutdownRequested,
    kProgramShutdownStopping,
    kProgramShutdownFinalizing
} program_shutdown_phase_e;

typedef struct signal_manager_s
{
    signal_handler_t handlers[kMaxSigHandles];
    unsigned int     handlers_len;
    // Deterministic result of exit-code arbitration: the first non-zero code
    // wins and a later zero can never overwrite it.
    atomic_int exit_code;
    // program_shutdown_phase_e stored atomically.
    atomic_int shutdown_phase;
#ifdef OS_WIN
    // Signaled near the end of teardown so a console close/logoff/shutdown
    // handler can return only after the main thread finished cleanup.
    void *shutdown_complete_event; // HANDLE
#else
    // Shutdown-control self-pipe. The POSIX signal handler writes the signal
    // number to [1] and requestProgramShutdown() writes a programmatic-request
    // marker to it; worker 0's loop reads [0] from a high-priority callback and
    // runs the real shutdown. It is dedicated control traffic and is therefore
    // never subject to the normal application event-admission gate.
    int shutdown_pipe[2];
#endif
    wmutex_t mutex;
    // Serializes the "claim the phase + hand off to worker 0" decision in
    // requestProgramShutdown(), so a concurrent requester observes the published
    // outcome of an in-flight handoff instead of inferring acceptance from a
    // phase whose wakeup may still fail.
    wmutex_t request_mutex;
    // Guarded by mutex. Set before worker 0 traverses the callback list so the
    // list cannot change under it, and so callbacks run exactly once.
    bool     callbacks_frozen;
    uint32_t started : 1;
    uint32_t raise_defaults : 1;
    uint32_t handle_sigint : 1;
    uint32_t handle_sigquit : 1;
    uint32_t handle_sighup : 1;
    uint32_t handle_sigill : 1;
    uint32_t handle_sigfpe : 1;
    uint32_t handle_sigabrt : 1;
    uint32_t handle_sigsegv : 1;
    uint32_t handle_sigterm : 1;
    uint32_t handle_sigpipe : 1;
    uint32_t handle_sigalrm : 1;

} signal_manager_t;

/**
 * @brief Create and initialize global signal manager state.
 *
 * @return signal_manager_t* Created signal manager.
 */
signal_manager_t *signalmanagerCreate(void);

/**
 * @brief Destroy global signal manager state.
 */
void signalmanagerDestroy(void);

/**
 * @brief Get global signal manager state.
 *
 * @return signal_manager_t* Current signal manager.
 */
signal_manager_t *signalmanagerGet(void);

/**
 * @brief Set global signal manager state pointer.
 *
 * @param sm Signal manager instance.
 */
void signalmanagerSet(signal_manager_t *sm);

/**
 * @brief Install configured signal handlers for current process.
 */
void signalmanagerStart(void);

/**
 * @brief Block the graceful (shutdown-routed) signals on the calling thread.
 *
 * Signal-mask policy: only the main thread has the handled stop signals
 * unblocked; every application-owned thread keeps them blocked. This is
 * enforced in two places that must agree:
 *   - threadCreate() blocks them around every thread spawn, so all threads
 *     created through it (workers, lwIP, TUN/raw/capture and later device
 *     threads) inherit the blocked mask even when they are created after
 *     signalmanagerStart();
 *   - this function is called on the main thread before workers are spawned and
 *     signalmanagerStart() then unblocks them on the main thread only.
 *
 * No-op on Windows, which uses the console control handler instead.
 */
void signalmanagerBlockHandledSignalsForCurrentThread(void);

/**
 * @brief Register a shutdown callback, executed once on worker 0 in LIFO order.
 *
 * Registrations are rejected once the callback list has been frozen for the
 * shutdown traversal (phase kProgramShutdownStopping and later).
 *
 * @param handle Callback function.
 * @param userdata Opaque callback context.
 */
void registerAtExitCallBack(SignalHandler handle, void *userdata);

/**
 * @brief Remove a previously registered shutdown callback.
 *
 * Ignored once the callback list has been frozen for the shutdown traversal.
 *
 * @param handle Callback function.
 * @param userdata Opaque callback context.
 */
void removeAtExitCallBack(SignalHandler handle, void *userdata);

/*
 * The three shutdown entry points (requestProgramShutdown, abortProgramNow and
 * the legacy terminateProgram) are declared in wlibc.h so every translation
 * unit sees them.
 */

/**
 * @brief Run the once-only main-thread shutdown sequence.
 *
 * Must only be called on WaterWall's main thread (worker 0). Normally the
 * process exits from inside this call. It returns only when another worker-0
 * pass already owns the shutdown sequence, in which case the caller must not
 * run cleanup itself.
 */
void signalmanagerRunShutdownOnMainThread(void);

/**
 * @brief Publish the transition into kProgramShutdownFinalizing.
 *
 * Called by the global-state teardown right before global resources are
 * destroyed. Idempotent.
 */
void signalmanagerEnterFinalizing(void);

/**
 * @brief Current process shutdown phase.
 */
program_shutdown_phase_e signalmanagerGetShutdownPhase(void);

bool signalmanagerIsTerminating(void);

/**
 * @brief Arbitrate @p exit_code into the process exit status.
 *
 * The first non-zero code wins; zero never overwrites a recorded error. Safe to
 * call concurrently from any thread.
 */
void signalmanagerSetExitCode(int exit_code);
int  signalmanagerGetExitCode(void);
