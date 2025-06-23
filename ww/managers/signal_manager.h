#pragma once

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
    wmutex_t         mutex;
    uint32_t         started : 1;
    uint32_t         handlers_ran : 1;
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

} signal_manager_t;

signal_manager_t *createSignalManager(void);
void              destroySignalManager(signal_manager_t *sm);
signal_manager_t *getSignalManager(void);
void              registerAtExitCallBack(SignalHandler handle, void *userdata);
void              removeAtExitCallBack(SignalHandler handle, void *userdata);
void              setSignalManager(signal_manager_t *sm);
void              startSignalManager(void);
