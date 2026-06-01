/*
 * Signal handling runtime and process termination dispatch.
 */

#include "signal_manager.h"
#include "global_state.h"

static signal_manager_t *signalmanager_gstate = NULL;

static const char *signalName(int signum)
{
    switch (signum)
    {
#ifdef SIGABRT
    case SIGABRT:
        return "SIGABRT";
#endif
#ifdef SIGALRM
    case SIGALRM:
        return "SIGALRM";
#endif
#ifdef SIGBUS
    case SIGBUS:
        return "SIGBUS";
#endif
#ifdef SIGFPE
    case SIGFPE:
        return "SIGFPE";
#endif
#ifdef SIGHUP
    case SIGHUP:
        return "SIGHUP";
#endif
#ifdef SIGILL
    case SIGILL:
        return "SIGILL";
#endif
#ifdef SIGINT
    case SIGINT:
        return "SIGINT";
#endif
#ifdef SIGPIPE
    case SIGPIPE:
        return "SIGPIPE";
#endif
#ifdef SIGQUIT
    case SIGQUIT:
        return "SIGQUIT";
#endif
#ifdef SIGSEGV
    case SIGSEGV:
        return "SIGSEGV";
#endif
#ifdef SIGTERM
    case SIGTERM:
        return "SIGTERM";
#endif
#ifdef SIGTRAP
    case SIGTRAP:
        return "SIGTRAP";
#endif
#ifdef SIGUSR1
    case SIGUSR1:
        return "SIGUSR1";
#endif
#ifdef SIGUSR2
    case SIGUSR2:
        return "SIGUSR2";
#endif
    default:
        return "UNKNOWN_SIGNAL";
    }
}

#if defined(OS_WIN)
static const char *windowsCtrlEventName(DWORD ctrl_type)
{
    switch (ctrl_type)
    {
    case CTRL_C_EVENT:
        return "CTRL_C_EVENT";
    case CTRL_BREAK_EVENT:
        return "CTRL_BREAK_EVENT";
    case CTRL_CLOSE_EVENT:
        return "CTRL_CLOSE_EVENT";
    case CTRL_LOGOFF_EVENT:
        return "CTRL_LOGOFF_EVENT";
    case CTRL_SHUTDOWN_EVENT:
        return "CTRL_SHUTDOWN_EVENT";
    default:
        return "UNKNOWN_WINDOWS_EVENT";
    }
}
#endif

/**
 * @brief Register one at-exit callback in reverse-priority slots.
 *
 * @param handle Callback function.
 * @param userdata Callback context.
 */
void registerAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(signalmanager_gstate != NULL);
    assert(signalmanager_gstate->handlers_len < kMaxSigHandles);
    mutexLock(&(signalmanager_gstate->mutex));
    for (int i = kMaxSigHandles - 1; i >= 0; i--)
    {
        if (signalmanager_gstate->handlers[i].handle == NULL)
        {
            signalmanager_gstate->handlers[i] = (signal_handler_t) {.handle = handle, .userdata = userdata};
            signalmanager_gstate->handlers_len++;
            mutexUnlock(&(signalmanager_gstate->mutex));

            return;
        }
    }
    mutexUnlock(&(signalmanager_gstate->mutex));

    printError("SignalManager: Too many atexit handlers, max is %d", kMaxSigHandles);
    _Exit(1);
}

/**
 * @brief Remove a previously registered at-exit callback.
 *
 * @param handle Callback function.
 * @param userdata Callback context.
 */
void removeAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(signalmanager_gstate != NULL);
    mutexLock(&(signalmanager_gstate->mutex));

    for (int i = 0; i < kMaxSigHandles; i++)
    {
        if (signalmanager_gstate->handlers[i].handle == handle &&
            signalmanager_gstate->handlers[i].userdata == userdata)
        {
            signalmanager_gstate->handlers[i] = (signal_handler_t) {.handle = NULL, .userdata = NULL};
            signalmanager_gstate->handlers_len--;
            mutexUnlock(&(signalmanager_gstate->mutex));

            return;
        }
    }
    // not found...
    mutexUnlock(&(signalmanager_gstate->mutex));
}


static void proceedWithNextExitHandler(void)
{
    for (unsigned int i = signalmanager_gstate->current_handler_index; i < kMaxSigHandles; i++)
    {
        if (signalmanager_gstate->handlers[i].handle != NULL)
        {
            signalmanager_gstate->current_handler_index = i + 1;
            signalmanager_gstate->handlers[i].handle(signalmanager_gstate->handlers[i].userdata, 0);
        }
    }
}

/**
 * @brief Execute all registered shutdown callbacks once.
 */
static void exitHandler(void)
{
    if (atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_relaxed))
    {
        const char *msg     = "SignalManager: Finished\n";
        int         written = write(STDOUT_FILENO, msg, stringLength(msg));
        discard     written;
        exit(1);
        return;
    }

    int     written = write(STDOUT_FILENO, "SignalManager: Exiting... \n", 27);
    discard written;

    atomicStoreExplicit(&GSTATE.application_stopping_flag, true, memory_order_release);


    proceedWithNextExitHandler();
}

#if defined(OS_WIN)

/**
 * @brief Windows console control dispatcher mapped to exit handler.
 *
 * @param CtrlType Windows control event code.
 * @return TRUE when handled, otherwise FALSE.
 */
static BOOL WINAPI CtrlHandler(_In_ DWORD CtrlType)
{
    // return TRUE;
    printError(
        "SignalManager: Received windows event %s (%lu)\n", windowsCtrlEventName(CtrlType), (unsigned long) CtrlType);

    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        exitHandler();
        _Exit(0);
        break;

    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        exitHandler();
        // operating system will automatically terminate the process after the handler completes.
        return TRUE;
    }
    return FALSE;
}
#endif

/**
 * @brief Multiplexed POSIX signal entry that routes to exit callbacks.
 *
 * @param signum Received signal number.
 */
static void multiplexedSignalHandler(int signum)
{
    static const char prefix[] = "SignalManager: Received signal ";
    static const char suffix[] = "\n";

    const char *name = signalName(signum);
    int         written;

    written = write(STDOUT_FILENO, prefix, sizeof(prefix) - 1);
    discard written;
    written = write(STDOUT_FILENO, name, stringLength(name));
    discard written;
    written = write(STDOUT_FILENO, suffix, sizeof(suffix) - 1);
    discard written;

    if (signalmanager_gstate == NULL || signalmanager_gstate->raise_defaults)
    {
        signal(signum, SIG_DFL);
    }
    // if (signum == SIGABRT)
    // {
    //     // assert fails in the handler, so we need to exit here
    //     signal(signum, SIG_DFL);
    //     raise(signum);

    // }

    exitHandler();

    // allowing normal exit
    if (signalmanager_gstate->raise_defaults)
    {
        raise(signum);
    }

    _Exit(128 + signum);
}

/**
 * @brief Install configured OS signal handlers.
 */
void signalmanagerStart(void)
{
    assert(signalmanager_gstate != NULL);

    if (signalmanager_gstate->started)
    {
        printError("Error double signalmanagerStart()");
        _Exit(1);
    }

    signalmanager_gstate->started = true;

#ifdef OS_WIN
    // Register the console control handler
    if (! SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        printError("Failed to set console control handler!");
        _Exit(1);
    }
#endif

    if (signalmanager_gstate->handle_sigint)
    {
        if (signal(SIGINT, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGINT signal handler");
            _Exit(1);
        }
    }

#ifndef OS_WIN

    if (signalmanager_gstate->handle_sigquit)
    {
        if (signal(SIGQUIT, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGQUIT signal handler");
            _Exit(1);
        }
    }
    if (signalmanager_gstate->handle_sighup)
    {
        if (signal(SIGHUP, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGHUP signal handler");
            _Exit(1);
        }
    }

#endif

    if (signalmanager_gstate->handle_sigill)
    {
        if (signal(SIGILL, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGILL signal handler");
            _Exit(1);
        }
    }
    if (signalmanager_gstate->handle_sigfpe)
    {
        if (signal(SIGFPE, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGFPE signal handler");
            _Exit(1);
        }
    }
    if (signalmanager_gstate->handle_sigabrt)
    {
        if (signal(SIGABRT, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGABRT signal handler");
            _Exit(1);
        }
    }
    if (signalmanager_gstate->handle_sigsegv)
    {
        if (signal(SIGSEGV, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGSEGV signal handler");
            _Exit(1);
        }
    }
    if (signalmanager_gstate->handle_sigterm)
    {
        if (signal(SIGTERM, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGTERM signal handler");
            _Exit(1);
        }
    }

#ifndef OS_WIN

    if (signalmanager_gstate->handle_sigpipe)
    {
        if (signal(SIGPIPE, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGPIPE signal handler");
            _Exit(1);
        }
    }

    if (signalmanager_gstate->handle_sigalrm)
    {
        if (signal(SIGALRM, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGALRM signal handler");
            _Exit(1);
        }
    }

#endif

    // wtimerAdd(getWorkerLoop(0), testCloseProgram, 3500, 0);
    // atexit(exitHandler);
}

// static WTHREAD_ROUTINE(TestThreadExit)
// {
//     discard userdata;
//     exitHandler();
//     return 0;
// }
// static void createCloseThread(wtimer_t *ev)
// {
//     discard ev;
//     threadCreate(TestThreadExit, NULL);
// }
signal_manager_t *signalmanagerCreate(void)
{
    assert(signalmanager_gstate == NULL);
    signalmanager_gstate = memoryAllocate(sizeof(signal_manager_t));

    *signalmanager_gstate = (signal_manager_t) {.handlers_len   = 0,
                                                .current_handler_index = 0,
                                                .started        = false,
                                                .raise_defaults = true,
                                                .handle_sigint  = true,
                                                .handle_sigquit = true,
                                                .handle_sighup  = false, // exits after ssh closed even with nohup
                                                .handle_sigill  = false,
                                                .handle_sigfpe  = true,
                                                .handle_sigabrt = false,
                                                .handle_sigsegv = false,
                                                .handle_sigterm = true,
                                                .handle_sigpipe = true,
                                                .handle_sigalrm = true};

    mutexInit(&(signalmanager_gstate->mutex));
    return signalmanager_gstate;
}

signal_manager_t *signalmanagerGet(void)
{
    assert(signalmanager_gstate != NULL);
    return signalmanager_gstate;
}

void signalmanagerSet(signal_manager_t *sm)
{
    assert(signalmanager_gstate == NULL);
    signalmanager_gstate = sm;
}
void signalmanagerDestroy(void)
{
    assert(signalmanager_gstate != NULL);
    mutexDestroy(&(signalmanager_gstate->mutex));
    memoryFree(signalmanager_gstate);
    signalmanager_gstate = NULL;
}

/**
 * @brief Terminate process after running registered exit handlers.
 *
 * @param exit_code Process exit code.
 */
_Noreturn void terminateProgram(int exit_code)
{

    if (signalmanager_gstate)
    {
        if (exit_code == 0)
        {
            printError("SignalManager: Terminating program with exit-code 0 after successful completion\n");
        }
        else
        {
            printError(
                "SignalManager: Terminating program with exit-code %d, please read above logs to understand why\n",
                exit_code);
        }

        // if (signalmanager_gstate->double_terminated)
        // {
        //     assert(false);
        //     const char msg[]   = "double terminated.\n";
        //     int        written = write(STDOUT_FILENO, msg, stringLength(msg));
        //     discard    written;
        //     exit(exit_code);
        // }
        // signalmanager_gstate->double_terminated = true;

        // termiateprogram is called when porccesing exit handlers, so we should not call exit handlers again to avoid
        // infinite loop
        if (atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_relaxed))
        {
            proceedWithNextExitHandler();
        }
        else
        {
            exitHandler();
        }

        // terminateCurrentThread();
    }
    else
    {
        // i dont like messy output when the program just exits because a file does not exists
        exit(exit_code);

        if (exit_code == 0)
        {
            printError("SignalManager: Terminating program with exit-code 0 after successful completion\n"
                       "Since signal manager is not initialized, we cannot run exit handlers, so just exiting now\n");
        }
        else
        {
            printError(
                "SignalManager: Terminating program with exit-code %d, please read above logs to understand why\n"
                "Since signal manager is not initialized, we cannot run exit handlers, so just exiting now\n",
                exit_code);
        }
    }
    exit(exit_code);
}

bool signalmanagerIsTerminating(void)
{
    return atomicLoadExplicit(&GSTATE.application_stopping_flag, memory_order_relaxed);
}
