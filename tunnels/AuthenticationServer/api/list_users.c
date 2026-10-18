#include "AuthenticationServer/api.h"

void authenticationserverApiCursor(const authenticationserver_page_view_t *view, size_t emitted, char cursor[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; ++i)
    {
        cursor[2 * i]     = hex[view->instance_id[i] >> 4];
        cursor[2 * i + 1] = hex[view->instance_id[i] & 15];
    }
    int length = snprintf(
        cursor + 32, 33, "%016" PRIx64 "%016" PRIx64, view->config_revision, (uint64_t) (view->position + emitted));
    assert(length == 32);
    discard length;
}

static void beginPage(authenticationserver_json_writer_t *w, const authenticationserver_page_view_t *view)
{
    authenticationserverJsonText(w, "{\"config_revision\":");
    authenticationserverJsonU64(w, view->config_revision);
    authenticationserverJsonText(w, ",\"stats_revision\":");
    authenticationserverJsonU64(w, view->stats_revision);
    authenticationserverJsonText(w, ",\"accounting_time_ms\":");
    authenticationserverJsonU64(w, view->accounting_time_ms);
    authenticationserverJsonText(w, ",\"total_users\":");
    authenticationserverJsonU64(w, view->total);
    authenticationserverJsonText(w, ",\"users\":[");
}

static void endPage(authenticationserver_json_writer_t *w, const authenticationserver_page_view_t *view, size_t emitted)
{
    authenticationserverJsonText(w, "],\"next_cursor\":");
    if (view->position + emitted == view->total)
        authenticationserverJsonText(w, "null");
    else
    {
        char cursor[65];
        authenticationserverApiCursor(view, emitted, cursor);
        authenticationserverJsonString(w, cursor);
    }
    authenticationserverJsonText(w, "}");
}

static void summary(authenticationserver_json_writer_t *w, const user_public_summary_t *u)
{
#define TEXT(s) authenticationserverJsonText(w, s)
#define NUMBER(key, value)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        TEXT("\"" key "\":");                                                                                          \
        authenticationserverJsonU64(w, value);                                                                         \
    } while (0)
    TEXT("{");
    NUMBER("id", u->id);
    TEXT(",");
    NUMBER("gid", u->gid);
    TEXT(",\"enabled\":");
    TEXT(u->enabled ? "true" : "false");
    TEXT(",\"name_preview\":");
    if (u->name_preview_state == kUserPublicNameInvalidEncoding)
        TEXT("null");
    else
        authenticationserverJsonString(w, u->name_preview);
    TEXT(",\"name_preview_state\":");
    authenticationserverJsonString(w,
                                   u->name_preview_state == kUserPublicNameComplete    ? "complete"
                                   : u->name_preview_state == kUserPublicNameTruncated ? "truncated"
                                                                                       : "invalid_encoding");
    TEXT(",\"traffic_limit\":{");
    NUMBER("u", u->traffic_limit.u);
    TEXT(",");
    NUMBER("d", u->traffic_limit.d);
    TEXT(",");
    NUMBER("total", u->traffic_limit.total);
    TEXT("},\"usage\":{");
    NUMBER("u", u->usage.u);
    TEXT(",");
    NUMBER("d", u->usage.d);
    TEXT("},\"time\":{");
    NUMBER("expire_at_ms", u->expire_at_ms);
    TEXT(",");
    NUMBER("expire_after_first_usage_ms", u->expire_after_first_usage_ms);
    TEXT(",");
    NUMBER("first_usage_at_ms", u->first_usage_at_ms);
    TEXT("}}");
#undef NUMBER
#undef TEXT
}

static void page(authenticationserver_json_writer_t *w, const void *value)
{
    const authenticationserver_page_view_t *view = value;
    beginPage(w, view);
    for (size_t i = 0; i < view->count && ! w->overflow && ! w->timeout; ++i)
    {
        if (i != 0)
            authenticationserverJsonText(w, ",");
        summary(w, &view->users[i]);
    }
    endPage(w, view, view->count);
}

api_result_t authenticationserverApiListUsers(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    authenticationserver_api_request_t request;
    const char *error = authenticationserverApiParse(message, context, kAuthenticationServerApiListUsers, &request);
    if (error != NULL)
        return authenticationserverApiError(context, error);
    authenticationserver_page_view_t view;
    error =
        authenticationserverCopyPageView(t, &request, context->working_memory_allowance, context->deadline_ms, &view);
    if (error != NULL)
        return authenticationserverApiError(context, error);
    const size_t charge = kAuthenticationServerApiScratchCharge + sizeof(view) + view.count * sizeof(*view.users);
    const size_t cap    = min((size_t) kAuthenticationServerApiBodyCap, context->max_response_body_size);
    authenticationserver_json_writer_t measured = {.capacity = cap, .deadline_ms = context->deadline_ms};
    beginPage(&measured, &view);
    size_t emitted = 0;
    for (size_t i = 0; i < view.count; ++i)
    {
        if (i != 0)
            authenticationserverJsonText(&measured, ",");
        summary(&measured, &view.users[i]);
        authenticationserver_json_writer_t complete = measured;
        endPage(&complete, &view, i + 1);
        buffer_pool_fit_t fit;
        if (complete.overflow || complete.timeout ||
            ! bufferpoolQueryBestFit(getCurrentEventWorkerBufferPool(), complete.used, 0, &fit) ||
            charge > context->working_memory_allowance ||
            fit.allocation_charge > context->working_memory_allowance - charge)
            break;
        emitted = i + 1;
    }
    api_result_t result = {.result_code = kApiResultError};
    if (view.count == 0 || emitted != 0)
    {
        view.count = emitted;
        result     = authenticationserverApiRender(context, kAuthenticationServerApiBodyCap, charge, page, &view);
    }
    memoryFree(view.users);
    if (result.buffer == NULL)
        return authenticationserverApiError(
            context, authenticationserverApiExpired(context->deadline_ms) ? "timeout" : "response_too_large");
    return result;
}
