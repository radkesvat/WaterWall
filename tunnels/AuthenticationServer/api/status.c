#include "AuthenticationServer/status.h"
#include "AuthenticationServer/api.h"
#include "AuthenticationServer/edit_token.h"

static void status(authenticationserver_json_writer_t *w, const void *value)
{
    const authenticationserver_status_t *s = value;
#define AUTH_JSON_TEXT(s) authenticationserverJsonText(w, s)
#define NUMBER(key, value)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        AUTH_JSON_TEXT("\"" key "\":");                                                                                \
        authenticationserverJsonU64(w, value);                                                                         \
    } while (0)
    AUTH_JSON_TEXT("{\"database_loaded\":");
    AUTH_JSON_TEXT(s->database_loaded ? "true" : "false");
    AUTH_JSON_TEXT(",\"database_dirty\":");
    AUTH_JSON_TEXT(s->database_dirty ? "true" : "false");
    AUTH_JSON_TEXT(",\"primary_checkpoint_valid\":");
    AUTH_JSON_TEXT(s->primary_checkpoint_valid ? "true" : "false");
    AUTH_JSON_TEXT(",");
    NUMBER("user_count", s->user_count);
    AUTH_JSON_TEXT(",");
    NUMBER("configured_producer_count", s->configured_producer_count);
    AUTH_JSON_TEXT(",");
    NUMBER("session_record_count", s->session_record_count);
    AUTH_JSON_TEXT(",");
    NUMBER("config_revision", s->config_revision);
    char token[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(s->instance_id, s->config_revision, token);
    AUTH_JSON_TEXT(",\"edit_token\":");
    authenticationserverJsonString(w, token);
    AUTH_JSON_TEXT(",");
    NUMBER("stats_revision", s->stats_revision);
    AUTH_JSON_TEXT(",\"primary_save\":{\"last_result\":");
    authenticationserverJsonString(w,
                                   s->primary_save_last_result == kAuthenticationServerSaveSuccess   ? "success"
                                   : s->primary_save_last_result == kAuthenticationServerSaveFailure ? "failure"
                                                                                                     : "not_attempted");
    AUTH_JSON_TEXT(",\"last_attempt_age_ms\":");
    if (s->primary_save_last_attempt_valid)
        authenticationserverJsonU64(w, s->primary_save_last_attempt_age_ms);
    else
        AUTH_JSON_TEXT("null");
    AUTH_JSON_TEXT(",\"last_success_age_ms\":");
    if (s->primary_save_last_success_valid)
        authenticationserverJsonU64(w, s->primary_save_last_success_age_ms);
    else
        AUTH_JSON_TEXT("null");
    AUTH_JSON_TEXT("},\"audit\":{\"enabled\":");
    AUTH_JSON_TEXT(s->audit.enabled ? "true" : "false");
    AUTH_JSON_TEXT(",\"healthy\":");
    AUTH_JSON_TEXT(s->audit.healthy ? "true" : "false");
    AUTH_JSON_TEXT(",");
    NUMBER("queued_records", s->audit.queued_records);
    AUTH_JSON_TEXT(",");
    NUMBER("written_records", s->audit.written_records);
    AUTH_JSON_TEXT(",");
    NUMBER("dropped_records", s->audit.dropped_records);
    AUTH_JSON_TEXT(",");
    NUMBER("write_failures", s->audit.write_failures);
    AUTH_JSON_TEXT(",\"last_error\":");
    if (s->audit.last_error != NULL)
        authenticationserverJsonString(w, s->audit.last_error);
    else
        AUTH_JSON_TEXT("null");
    AUTH_JSON_TEXT("}}");
#undef NUMBER
#undef AUTH_JSON_TEXT
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
