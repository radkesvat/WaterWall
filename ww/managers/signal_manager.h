#pragma once

/*
 * Signal manager API for shutdown handlers and process termination flow.
 */

#include "application_shutdown.h"
#include "wlibc.h"
#include "wmutex.h"

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

typedef struct signal_manager_s
{
    signal_handler_t handlers[kMaxSigHandles];
    unsigned int     handlers_len;
#ifdef OS_WIN
    // Signaled near the end of teardown so a console close/logoff/shutdown
    // handler can return only after the main thread finished cleanup.
    void *shutdown_complete_event; // HANDLE
    bool  console_handler_registered;
#else
    // Shutdown-control self-pipe. The POSIX handler publishes a signal-safe
    // mailbox value and writes a best-effort wake edge to [1].
    int shutdown_pipe[2];
#endif
    wmutex_t mutex;
    // Guarded by mutex. Set before the late observer traversal so the list
    // cannot change under it and every observer runs exactly once.
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
bool signalmanagerStart(void);

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

/** Translate any signal-safe mailbox value into the durable controller state. */
void signalmanagerConsumePendingShutdownSignal(void);

/**
 * @brief Arbitrate a startup failure against any already-pending graceful signal.
 *
 * On POSIX, the graceful set remains blocked across mailbox consumption and
 * both typed controller publications. The caller's exact previous mask is
 * restored before return. On Windows, the controller mutex provides the
 * corresponding arbitration boundary against console requests.
 */
application_shutdown_request_result_e signalmanagerArbitrateStartupFailure(int exit_code);

#if defined(SIGNAL_MANAGER_TEST_HOOKS) && defined(OS_WIN)
bool signalmanagerTestDispatchWindowsConsoleEvent(unsigned long ctrl_type);
void signalmanagerTestSetWindowsBeforeEntryHook(void (*hook)(void *), void *context);
#elif defined(SIGNAL_MANAGER_TEST_HOOKS)
void signalmanagerTestSetPosixMailboxHook(void (*hook)(void));
#endif

/**
 * @brief Register a late non-owning exit observer, executed once in LIFO order.
 *
 * Registrations are rejected once the callback list has been frozen.
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
 * Shutdown entry points are declared in wlibc.h so every translation unit sees
 * them.
 */

/**
 * @brief Run retained late, non-owning exit observers exactly once.
 */
void signalmanagerRunExitObservers(void);

/**
 * @brief Request shutdown for a local failure without racing an accepted result.
 *
 * Unlike requestProgramShutdown(), a non-zero @p exit_code is not recorded when
 * another thread already completed the shutdown handoff. This is for terminal
 * reconciliation whose own queue refusal can be caused by that accepted
 * shutdown. It returns false only when no orderly handoff exists.
 */
bool signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code);

/**
 * @brief Arbitrate @p exit_code into the process exit status.
 *
 * The first non-zero code wins; zero never overwrites a recorded error. Safe to
 * call concurrently from any thread.
 */
