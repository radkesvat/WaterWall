#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef enum ww_lifecycle_scope_e
{
    kWwLifecycleProcessShutdown = 0,
    kWwLifecycleStartupRollback,
    kWwLifecycleOwnedChildStop,
    kWwLifecycleDeviceRestart
} ww_lifecycle_scope_e;

typedef enum ww_lifecycle_close_policy_e
{
    kWwLifecycleCloseGraceful = 0,
    kWwLifecycleCloseAbortive
} ww_lifecycle_close_policy_e;

typedef struct ww_lifecycle_context_s
{
    ww_lifecycle_scope_e        scope;
    ww_lifecycle_close_policy_e close_policy;
} ww_lifecycle_context_t;

static inline bool wwLifecycleIsProcessShutdown(const ww_lifecycle_context_t *context)
{
    return context != NULL && context->scope == kWwLifecycleProcessShutdown;
}

static inline const ww_lifecycle_context_t *wwLifecycleProcessShutdown(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleProcessShutdown,
        .close_policy = kWwLifecycleCloseGraceful,
    };
    return &context;
}

static inline const ww_lifecycle_context_t *wwLifecycleStartupRollback(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleStartupRollback,
        .close_policy = kWwLifecycleCloseAbortive,
    };
    return &context;
}

static inline const ww_lifecycle_context_t *wwLifecycleOwnedChildStop(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleOwnedChildStop,
        .close_policy = kWwLifecycleCloseAbortive,
    };
    return &context;
}

static inline const ww_lifecycle_context_t *wwLifecycleDeviceRestart(void)
{
    static const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleDeviceRestart,
        .close_policy = kWwLifecycleCloseAbortive,
    };
    return &context;
}
