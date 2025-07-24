#include "signal_manager.h"
#include "global_state.h"

static signal_manager_t *state = NULL;


void registerAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(state != NULL);
    assert(state->handlers_len < kMaxSigHandles);
    mutexLock(&(state->mutex));
    for (int i = kMaxSigHandles - 1; i >= 0; i--)
    {
        if (state->handlers[i].handle == NULL)
        {
            state->handlers[i] = (signal_handler_t){.handle = handle, .userdata = userdata};
            state->handlers_len++;
            mutexUnlock(&(state->mutex));

            return;
        }
    }
    mutexUnlock(&(state->mutex));

    printError("SignalManager: Too many atexit handlers, max is %d", kMaxSigHandles);
    _Exit(1);
}

void removeAtExitCallBack(SignalHandler handle, void *userdata)
{
    assert(state != NULL);
    mutexLock(&(state->mutex));

    for (int i = 0; i < kMaxSigHandles; i++)
    {
        if (state->handlers[i].handle == handle && state->handlers[i].userdata == userdata)
        {
            state->handlers[i] = (signal_handler_t){.handle = NULL, .userdata = NULL};
            state->handlers_len--;
            mutexUnlock(&(state->mutex));

            return;
        }
    }
    // not found...
    mutexUnlock(&(state->mutex));
}

static bool exit_handler_ran_once = false;
static void exitHandler(void)
{
    if (exit_handler_ran_once)
    {
        const char *msg     = "SignalManager: Finished\n";
        int         written = write(STDOUT_FILENO, msg, stringLength(msg));
        discard     written;
        exit(1);
        return;
    }

    int     written = write(STDOUT_FILENO, "SignalManager: Exiting... \n", 27);
    discard written;

    exit_handler_ran_once = true;

    for (unsigned int i = 0; i < kMaxSigHandles; i++)
    {
        if (state->handlers[i].handle != NULL)
        {
            // written = write(STDOUT_FILENO, ".", 1);
            // discard written;
            state->handlers[i].handle(state->handlers[i].userdata, 0);
        }
    }
}

#if defined(OS_WIN)

static BOOL WINAPI CtrlHandler(_In_ DWORD CtrlType)
{
    // return TRUE;
    printError("SignalManager: Received windows event %d\n", CtrlType);

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

static void multiplexedSignalHandler(int signum)
{
    char    message[50];
    int     length  = snprintf(message, sizeof(message), "SignalManager: Received signal %d\n", signum);
    int     written = write(STDOUT_FILENO, message, length);
    discard written;

    if (state->raise_defaults)
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
    if (state->raise_defaults)
    {
        raise(signum);

        // written = write(STDOUT_FILENO,
        //                 "SignalManager: The program should have been terminated before this, exiting...\n", 75);
        // discard written;
        // _Exit(1);
    }
}

void signalmanagerStart(void)
{
    assert(state != NULL);

    if (state->started)
    {
        printError("Error double signalmanagerStart()");
        _Exit(1);
    }

    state->started = true;

#ifdef OS_WIN
    // Register the console control handler
    if (! SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        printError("Failed to set console control handler!");
        _Exit(1);
    }
#endif

    if (state->handle_sigint)
    {
        if (signal(SIGINT, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGINT signal handler");
            _Exit(1);
        }
    }

#ifndef OS_WIN

    if (state->handle_sigquit)
    {
        if (signal(SIGQUIT, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGQUIT signal handler");
            _Exit(1);
        }
    }
    if (state->handle_sighup)
    {
        if (signal(SIGHUP, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGHUP signal handler");
            _Exit(1);
        }
    }

#endif

    if (state->handle_sigill)
    {
        if (signal(SIGILL, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGILL signal handler");
            _Exit(1);
        }
    }
    if (state->handle_sigfpe)
    {
        if (signal(SIGFPE, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGFPE signal handler");
            _Exit(1);
        }
    }
    if (state->handle_sigabrt)
    {
        if (signal(SIGABRT, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGABRT signal handler");
            _Exit(1);
        }
    }
    if (state->handle_sigsegv)
    {
        if (signal(SIGSEGV, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGSEGV signal handler");
            _Exit(1);
        }
    }
    if (state->handle_sigterm)
    {
        if (signal(SIGTERM, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGTERM signal handler");
            _Exit(1);
        }
    }

#ifndef OS_WIN

    if (state->handle_sigpipe)
    {
        if (signal(SIGPIPE, multiplexedSignalHandler) == SIG_ERR)
        {
            printError("Error setting SIGPIPE signal handler");
            _Exit(1);
        }
    }

    if (state->handle_sigalrm)
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
    assert(state == NULL);
    state = memoryAllocate(sizeof(signal_manager_t));

    *state = (signal_manager_t){.handlers_len   = 0,
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

    mutexInit(&(state->mutex));
    return state;
}

signal_manager_t *signalmanagerGet(void)
{
    assert(state != NULL);
    return state;
}

void signalmanagerSet(signal_manager_t *sm)
{
    assert(state == NULL);
    state = sm;
}
void signalmanagerDestroy(void)
{
    assert(state != NULL);
    mutexDestroy(&(state->mutex));
    memoryFree(state);
}

_Noreturn void terminateProgram(int exit_code)
{

    if (state)
    {
        printError("SignalManager: Terminating program with exit-code %d, please read above logs to understand why\n",
                   exit_code);

        if (state->double_terminated)
        {
            assert(false);
            const char msg[]   = "double terminated.\n";
            int        written = write(STDOUT_FILENO, msg, stringLength(msg));
            discard    written;
            exit(exit_code);
        }
        state->double_terminated = true;

        exitHandler();
        // terminateCurrentThread();
    }
    else
    {
        printError("SignalManager: Terminating program with exit-code %d, please read above logs to understand why\n",
                   "Since signal manager is not initialized, we cannot run exit handlers, so just exiting now",
                   exit_code);
    }
    exit(exit_code);
}
