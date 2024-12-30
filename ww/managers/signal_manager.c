#include "signal_manager.h"
#include "hplatform.h"

static signal_manager_t *state = NULL;

void registerAtExitCallback(SignalHandler handle, void *userdata)
{
    assert(state != NULL);
    assert(state->handlers_len < kMaxSigHandles);
    state->handlers[state->handlers_len++] = (signal_handler_t) {.handle = handle, .userdata = userdata};
}

signal_manager_t *createSignalManager(void)
{
    assert(state == NULL);
    state = memoryAllocate(sizeof(signal_manager_t));

    *state = (signal_manager_t) {.handlers_len   = 0,
                                 .started        = false,
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

static void multiplexedSignalHandler(int signum)
{
    char message[50];
    int  length = snprintf(message, sizeof(message), "SignalManager: Received signal %d\n", signum);
    int unused = write(STDOUT_FILENO, message, length);
    (void) unused;

    if (state->raise_defaults)
    {
        signal(signum, SIG_DFL);
    }

    for (unsigned int i = 0; i < state->handlers_len; i++)
    {
        state->handlers[i].handle(state->handlers[i].userdata, signum);
    }

    if (state->raise_defaults)
    {
        raise(signum);
    }
}

static void multiplexedSignalHandlerNoArg(void)
{
    // static const char kMessage[] = "SignalManager: Executing exit callabck\n";
    // int  unused = write(STDOUT_FILENO, kMessage, sizeof(kMessage) - 1);
    // (void) unused;

    for (unsigned int i = 0; i < state->handlers_len; i++)
    {
        state->handlers[i].handle(state->handlers[i].userdata, 0);
    }
}

void startSignalManager(void)
{
    assert(state != NULL);
    if (state->started)
    {
        perror("Error double startSignalManager()");
        exit(1);
    }

    state->started = true;

    if (state->handle_sigint)
    {
        if (signal(SIGINT, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGINT signal handler");
            exit(1);
        }
    }

#ifndef OS_WIN

    if (state->handle_sigquit)
    {
        if (signal(SIGQUIT, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGQUIT signal handler");
            exit(1);
        }
    }
    if (state->handle_sighup)
    {
        if (signal(SIGHUP, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGHUP signal handler");
            exit(1);
        }
    }

#endif

    if (state->handle_sigill)
    {
        if (signal(SIGILL, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGILL signal handler");
            exit(1);
        }
    }
    if (state->handle_sigfpe)
    {
        if (signal(SIGFPE, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGFPE signal handler");
            exit(1);
        }
    }
    if (state->handle_sigabrt)
    {
        if (signal(SIGABRT, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGABRT signal handler");
            exit(1);
        }
    }
    if (state->handle_sigsegv)
    {
        if (signal(SIGSEGV, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGSEGV signal handler");
            exit(1);
        }
    }
    if (state->handle_sigterm)
    {
        if (signal(SIGTERM, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGTERM signal handler");
            exit(1);
        }
    }

#ifndef OS_WIN

    if (state->handle_sigpipe)
    {
        if (signal(SIGPIPE, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGPIPE signal handler");
            exit(1);
        }
    }

    if (state->handle_sigalrm)
    {
        if (signal(SIGALRM, multiplexedSignalHandler) == SIG_ERR)
        {
            perror("Error setting SIGALRM signal handler");
            exit(1);
        }
    }
    
#endif

    atexit(multiplexedSignalHandlerNoArg);
}
