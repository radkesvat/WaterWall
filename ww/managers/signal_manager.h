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

typedef struct signal_manager_s
{
    signal_handler_t handlers[kMaxSigHandles];
    unsigned int     handlers_len;
    unsigned int     current_handler_index;
    atomic_int       exit_code;
    // Set by the first shutdown requester (signal / console / terminateProgram).
    // A duplicate request escalates to an immediate process exit.
    atomic_bool      shutdown_requested;
#ifdef OS_WIN
    // Signaled near the end of teardown so a console close/logoff/shutdown
    // handler can return only after the main thread finished cleanup.
    void            *shutdown_complete_event; // HANDLE
#else
    // self-pipe: signal handler writes the signal byte to [1]; worker 0's loop
    // reads [0] from a high-priority callback and runs the real shutdown.
    int              shutdown_pipe[2];
#endif
    wmutex_t         mutex;
    uint32_t         started : 1;
    uint32_t         raise_defaults : 1;
    uint32_t         handle_sigint : 1;
    uint32_t         handle_sigquit : 1;
    uint32_t         handle_sighup : 1;
    uint32_t         handle_sigill : 1;
    uint32_t         handle_sigfpe : 1;
    uint32_t         handle_sigabrt : 1;
    uint32_t         handle_sigsegv : 1;
    uint32_t         handle_sigterm : 1;
    uint32_t         handle_sigpipe : 1;
    uint32_t         handle_sigalrm : 1;
    uint32_t         double_terminated : 1;

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
 * Called on the main thread before workers are spawned so worker threads
 * inherit the blocked mask; graceful signals are then unblocked on the main
 * thread inside signalmanagerStart(). This keeps signal delivery on the main
 * thread and out of the worker event loops. No-op on Windows.
 */
void signalmanagerBlockHandledSignalsForCurrentThread(void);

/**
 * @brief Register callback invoked during exit/signal shutdown sequence.
 *
 * @param handle Callback function.
 * @param userdata Opaque callback context.
 */
void registerAtExitCallBack(SignalHandler handle, void *userdata);

/**
 * @brief Remove a previously registered exit callback.
 *
 * @param handle Callback function.
 * @param userdata Opaque callback context.
 */
void removeAtExitCallBack(SignalHandler handle, void *userdata);

// void terminateProgram(int exit_code); in wlibc.h

bool signalmanagerIsTerminating(void);

void signalmanagerSetExitCode(int exit_code);
int  signalmanagerGetExitCode(void);
