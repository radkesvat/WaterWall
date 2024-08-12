#include "signal_manager.h"

static signal_manager_t *state = NULL;

void registerAtExitCallback(SignalHandler handle)
{
    assert(state != NULL);
    assert(state->handlers_len < kMaxSigHandles);
    state->handlers[state->handlers_len++] = handle;
}

signal_manager_t *createSignalManager(void)
{
    assert(state == NULL);
    state = globalMalloc(sizeof(signal_manager_t));

    *state = (signal_manager_t) {.handlers_len   = 0,
                                 .started        = false,
                                 .raise_defaults = true,
                                 .handle_sigint  = true,
                                 .handle_sigquit = true,
                                 .handle_sighup  = true,
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
    if (state->raise_defaults)
    {
        signal(signum, SIG_DFL);
    }

    for (unsigned int i = 0; i < state->handlers_len; i++)
    {
        state->handlers[i](signum);
    }

    if (state->raise_defaults)
    {
        raise(signum);
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
}
