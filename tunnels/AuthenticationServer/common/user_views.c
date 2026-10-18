#include "AuthenticationServer/api.h"

const char *authenticationserverApiPublicError(user_public_result_t result)
{
    switch (result)
    {
    case kUserPublicOk:
        return NULL;
    case kUserPublicBusy:
        return "busy";
    case kUserPublicTimeout:
        return "timeout";
    case kUserPublicNotFound:
        return "not_found";
    case kUserPublicOutOfRange:
        return "invalid_cursor";
    case kUserPublicTooLarge:
        return "record_too_large";
    case kUserPublicInvalidEncoding:
        return "invalid_record_encoding";
    }
    assert(false);
    return "invalid_request";
}

const char *authenticationserverCopyUserView(tunnel_t *t, uint64_t id, size_t allowance, uint64_t deadline_ms,
                                             authenticationserver_user_view_t *view)
{
    *view = (authenticationserver_user_view_t) {0};
    if (authenticationserverApiExpired(deadline_ms))
        return "timeout";
    if (allowance <= kAuthenticationServerApiScratchCharge + sizeof(*view))
        return "record_too_large";
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (! rwlockTryReadLock(&ts->state_lock))
        return "busy";
    size_t               string_allowance = min((size_t) kAuthenticationServerApiBodyCap,
                                  allowance - kAuthenticationServerApiScratchCharge - sizeof(*view));
    user_public_result_t result =
        usersCopyPublicDetailByIdentifier(&ts->store.users, id, string_allowance, deadline_ms, &view->user);
    if (result == kUserPublicOk)
    {
        view->config_revision    = ts->store.config_revision;
        view->stats_revision     = ts->store.stats_revision;
        view->accounting_time_ms = authenticationserverAccountingTimeMS(ts);
    }
    rwlockReadUnlock(&ts->state_lock);
    if (authenticationserverApiExpired(deadline_ms))
    {
        userPublicDetailDestroy(&view->user);
        return "timeout";
    }
    return authenticationserverApiPublicError(result);
}

const char *authenticationserverCopyPageView(tunnel_t *t, const authenticationserver_api_request_t *request,
                                             size_t allowance, uint64_t deadline_ms,
                                             authenticationserver_page_view_t *view)
{
    *view = (authenticationserver_page_view_t) {0};
    if (authenticationserverApiExpired(deadline_ms))
        return "timeout";
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (! rwlockTryReadLock(&ts->state_lock))
        return "busy";
    const char *error = NULL;
    if (request->has_cursor &&
        (memcmp(request->instance_id, ts->api_instance_id, 16) != 0 || request->revision != ts->store.config_revision))
        error = "stale_cursor";
    size_t total = 0;
    if (error == NULL)
        error = authenticationserverApiPublicError(usersTryCount(&ts->store.users, deadline_ms, &total));
    if (error == NULL && (request->position > SIZE_MAX || request->position > total))
        error = "invalid_cursor";
    size_t count = 0;
    if (error == NULL)
    {
        view->position    = (size_t) request->position;
        count             = min(request->limit, total - view->position);
        const size_t base = kAuthenticationServerApiScratchCharge + sizeof(*view);
        /* Reserve both the snapshot and its final pool allocation. Use a
         * conservative escaped-summary bound to select capacity without
         * inspecting extra records. A single short summary may fit even when
         * that worst case does not, so always try one if its snapshot fits. */
        while (count > 1)
        {
            buffer_pool_fit_t fit;
            const size_t      snapshot_charge = base + count * sizeof(*view->users);
            if (snapshot_charge <= allowance &&
                bufferpoolQueryBestFit(getCurrentEventWorkerBufferPool(), 512 + count * 2560, 0, &fit) &&
                fit.allocation_charge <= allowance - snapshot_charge)
                break;
            --count;
        }
        if (count != 0 && (allowance < base || sizeof(*view->users) > allowance - base))
            count = 0;
        if (total > view->position && count == 0)
            error = "response_too_large";
    }
    if (error == NULL)
    {
        if (count != 0)
        {
            view->users = memoryAllocate(count * sizeof(*view->users));
            error       = authenticationserverApiPublicError(usersCopyPublicPage(
                &ts->store.users, view->position, count, deadline_ms, view->users, &view->count, &view->total));
        }
        else
            view->total = total;
        view->config_revision    = ts->store.config_revision;
        view->stats_revision     = ts->store.stats_revision;
        view->accounting_time_ms = authenticationserverAccountingTimeMS(ts);
        memoryCopy(view->instance_id, ts->api_instance_id, 16);
    }
    rwlockReadUnlock(&ts->state_lock);
    if (authenticationserverApiExpired(deadline_ms))
        error = "timeout";
    if (error != NULL)
    {
        memoryFree(view->users);
        *view = (authenticationserver_page_view_t) {0};
    }
    return error;
}
