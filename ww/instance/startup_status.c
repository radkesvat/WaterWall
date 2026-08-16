#include "startup.h"

static thread_local ww_startup_context_t *startup_current_context;

void wwStartupResultMerge(ww_startup_result_t *destination, ww_startup_result_t source)
{
    assert(destination != NULL);
    if (destination->exit_code == 0 && source.exit_code != 0)
    {
        destination->exit_code = source.exit_code;
    }
}

void wwStartupContextBegin(ww_startup_context_t *context)
{
    assert(context != NULL);
    assert(! context->active);
    context->result         = wwStartupSuccess();
    context->parent         = startup_current_context;
    context->active         = true;
    startup_current_context = context;
}

ww_startup_result_t wwStartupContextEnd(ww_startup_context_t *context)
{
    assert(context != NULL);
    assert(context->active);
    assert(startup_current_context == context);

    startup_current_context = context->parent;
    context->active         = false;
    if (startup_current_context != NULL)
    {
        wwStartupResultMerge(&startup_current_context->result, context->result);
    }
    return context->result;
}

void startupFailureRecord(int exit_code)
{
    assert(startup_current_context != NULL);
    if (startup_current_context != NULL)
    {
        wwStartupResultMerge(&startup_current_context->result, wwStartupFailure(exit_code));
    }
}

bool startupFailurePending(void)
{
    assert(startup_current_context != NULL);
    return startup_current_context != NULL && ! wwStartupSucceeded(startup_current_context->result);
}

int startupFailureCode(void)
{
    assert(startup_current_context != NULL);
    return startup_current_context != NULL ? startup_current_context->result.exit_code : 1;
}
