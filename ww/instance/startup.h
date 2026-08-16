#pragma once

#include "wlibc.h"

typedef struct ww_startup_result_s
{
    int exit_code;
} ww_startup_result_t;

typedef struct ww_startup_context_s
{
    ww_startup_result_t          result;
    struct ww_startup_context_s *parent;
    bool                         active;
} ww_startup_context_t;

static inline ww_startup_result_t wwStartupSuccess(void)
{
    return (ww_startup_result_t) {0};
}

static inline ww_startup_result_t wwStartupFailure(int exit_code)
{
    return (ww_startup_result_t) {.exit_code = exit_code != 0 ? exit_code : 1};
}

static inline bool wwStartupSucceeded(ww_startup_result_t result)
{
    return result.exit_code == 0;
}

void                wwStartupContextBegin(ww_startup_context_t *context);
ww_startup_result_t wwStartupContextEnd(ww_startup_context_t *context);
void                wwStartupResultMerge(ww_startup_result_t *destination, ww_startup_result_t source);

void startupFailureRecord(int exit_code);
bool startupFailurePending(void);
int  startupFailureCode(void);
