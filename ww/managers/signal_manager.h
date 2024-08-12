#pragma once

#include "ww.h"

typedef void (*SignalHandler)(int signum);

enum
{
    kMaxSigHandles = 16
};

typedef struct signal_manager_s
{
    SignalHandler handlers[kMaxSigHandles];
    unsigned int  handlers_len;
    bool          started;
    bool          raise_defaults;
    bool          handle_sigint;
    bool          handle_sigquit;
    bool          handle_sighup;
    bool          handle_sigill;
    bool          handle_sigfpe;
    bool          handle_sigabrt;
    bool          handle_sigsegv;
    bool          handle_sigterm;
    bool          handle_sigpipe;
    bool          handle_sigalrm;

} signal_manager_t;

signal_manager_t *createSignalManager(void);
signal_manager_t *getSignalManager(void);
void              registerAtExitCallback(SignalHandler handle);
void              setSignalManager(signal_manager_t *sm);
void              startSignalManager(void);
