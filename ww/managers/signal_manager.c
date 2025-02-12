#include "signal_manager.h"

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
            state->handlers[i] = (signal_handler_t) {.handle = handle, .userdata = userdata};
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
            state->handlers[i] = (signal_handler_t) {.handle = NULL, .userdata = NULL};
            state->handlers_len--;
            mutexUnlock(&(state->mutex));

            return;
        }
    }
    // not found...
    mutexUnlock(&(state->mutex));
}

signal_manager_t *createSignalManager(void)
{
    assert(state == NULL);
    state = memoryAllocate(sizeof(signal_manager_t));

    *state = (signal_manager_t) {.handlers_len   = 0,
                                 .started        = false,
                                 .handlers_ran   = false,
                                 .raise_defaults = true,
                                 .handle_sigint  = true,
                                 .handle_sigquit = true,
                                 .handle_sighup  = false, // exits after ssh closed even with nohup
                                 .handle_sigill  = true,
                                 .handle_sigfpe  = true,
                                 .handle_sigabrt = true,
                                 .handle_sigsegv = true,
                                 .handle_sigterm = true,
                                 .handle_sigpipe = true,
                                 .handle_sigalrm = true};

    mutexInit(&(state->mutex));
    return state;
}

signal_manager_t *getSignalManager(void)
{
    assert(state != NULL);
    return state;
}

void setSignalManager(signal_manager_t *sm)
{
    assert(state == NULL);
    state = sm;
}

static void exitHandler(void)
{
    if (state->handlers_ran)
    {
        const char *msg     = "SignalManager: Not running signal handlers again!, gracefully exiting\n";
        int         written = (int) write(STDOUT_FILENO, msg, stringLength(msg));
        (void) written;
        _Exit(1); // exit(1) will call the atexit handlers again
        return;
    }

    state->handlers_ran = true;

    for (unsigned int i = 0; i < kMaxSigHandles; i++)
    {
        if (state->handlers[i].handle != NULL)
        {
            state->handlers[i].handle(state->handlers[i].userdata, 0);
        }
    }
}

#if defined(OS_WIN)

static BOOL WINAPI CtrlHandler(_In_ DWORD CtrlType)
{
    printError("SignalManager: Received windows event %d", CtrlType);

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
    char message[50];
    int  length  = snprintf(message, (size_t) sizeof(message), "SignalManager: Received signal %d\n", signum);
    int  written = (int) write(STDOUT_FILENO, message, (size_t) length);
    (void) written;

    if (state->raise_defaults)
    {
        signal(signum, SIG_DFL);
    }

    exitHandler();

    if (state->raise_defaults)
    {
        raise(signum); // maybe this later calls our handler again (atexit call) but its already guarded

        // written = write(STDOUT_FILENO,
        //                 "SignalManager: The program should have been terminated before this, exiting...\n", 75);
        // (void) written;
        // _Exit(1);
    }
}

void startSignalManager(void)
{
    assert(state != NULL);

    if (state->started)
    {
        printError("Error double startSignalManager()");
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

    atexit(exitHandler);
}

void destroySignalManager(signal_manager_t *sm)
{
    assert(sm != NULL);
    mutexDestroy(&(sm->mutex));
    memoryFree(sm);
}
