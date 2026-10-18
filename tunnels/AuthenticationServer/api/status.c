#include "AuthenticationServer/status.h"
#include "AuthenticationServer/api.h"

static void status(authenticationserver_json_writer_t *w, const void *value)
{
    const authenticationserver_status_t *s = value;
#define TEXT(s) authenticationserverJsonText(w, s)
#define NUMBER(key, value)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        TEXT("\"" key "\":");                                                                                          \
        authenticationserverJsonU64(w, value);                                                                         \
    } while (0)
    TEXT("{\"database_loaded\":");
    TEXT(s->database_loaded ? "true" : "false");
    TEXT(",");
    NUMBER("user_count", s->user_count);
    TEXT(",");
    NUMBER("configured_producer_count", s->configured_producer_count);
    TEXT(",");
    NUMBER("session_record_count", s->session_record_count);
    TEXT(",");
    NUMBER("config_revision", s->config_revision);
    TEXT(",");
    NUMBER("stats_revision", s->stats_revision);
    TEXT(",\"primary_save\":{\"last_result\":");
    authenticationserverJsonString(w,
                                   s->primary_save_last_result == kAuthenticationServerSaveSuccess   ? "success"
                                   : s->primary_save_last_result == kAuthenticationServerSaveFailure ? "failure"
                                                                                                     : "not_attempted");
    TEXT(",\"last_attempt_age_ms\":");
    if (s->primary_save_last_attempt_valid)
        authenticationserverJsonU64(w, s->primary_save_last_attempt_age_ms);
    else
        TEXT("null");
    TEXT(",\"last_success_age_ms\":");
    if (s->primary_save_last_success_valid)
        authenticationserverJsonU64(w, s->primary_save_last_success_age_ms);
    else
        TEXT("null");
    TEXT("}}");
#undef NUMBER
#undef TEXT
}

api_result_t authenticationserverApiStatus(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    authenticationserver_api_request_t request;
    const char *error = authenticationserverApiParse(message, context, kAuthenticationServerApiStatus, &request);
    if (error != NULL)
        return authenticationserverApiError(context, error);
    authenticationserver_status_t        snapshot;
    authenticationserver_status_result_t copied =
        authenticationserverStatusSnapshot(t, context->deadline_ms, &snapshot);
    if (copied != kAuthenticationServerStatusOk)
        return authenticationserverApiError(context, copied == kAuthenticationServerStatusBusy ? "busy" : "timeout");
    api_result_t result =
        authenticationserverApiRender(context, 4096, kAuthenticationServerApiScratchCharge, status, &snapshot);
    if (result.buffer == NULL)
        return authenticationserverApiError(
            context, authenticationserverApiExpired(context->deadline_ms) ? "timeout" : "response_too_large");
    return result;
}
