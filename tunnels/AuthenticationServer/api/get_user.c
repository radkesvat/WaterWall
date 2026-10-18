#include "AuthenticationServer/api.h"
#include "AuthenticationServer/edit_token.h"

static void detail(authenticationserver_json_writer_t *w, const void *value)
{
    const authenticationserver_user_view_t *view = value;
    const user_public_detail_t             *u    = &view->user;
#define TEXT(s) authenticationserverJsonText(w, s)
#define NUMBER(key, value)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        TEXT("\"" key "\":");                                                                                          \
        authenticationserverJsonU64(w, value);                                                                         \
    } while (0)
#define STRING(key, value)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        TEXT("\"" key "\":");                                                                                          \
        authenticationserverJsonString(w, value);                                                                      \
    } while (0)
    TEXT("{");
    NUMBER("config_revision", view->config_revision);
    char token[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(view->instance_id, view->config_revision, token);
    TEXT(",\"edit_token\":");
    authenticationserverJsonString(w, token);
    TEXT(",");
    NUMBER("stats_revision", view->stats_revision);
    TEXT(",");
    NUMBER("accounting_time_ms", view->accounting_time_ms);
    TEXT(",\"user\":{");
    NUMBER("id", u->id);
    TEXT(",");
    NUMBER("gid", u->gid);
    TEXT(",\"enabled\":");
    TEXT(u->enabled ? "true" : "false");
    TEXT(",");
    STRING("name", u->name);
    TEXT(",");
    STRING("email", u->email);
    TEXT(",");
    STRING("notes", u->notes);
    TEXT(",");
    STRING("wireguard_allowed_ips", u->wireguard_allowed_ips);
    TEXT(",");
    NUMBER("record_stat_interval_ms", u->record_stat_interval_ms);
    TEXT(",\"limit\":{\"traffic\":{");
    NUMBER("u", u->limit.traffic.u);
    TEXT(",");
    NUMBER("d", u->limit.traffic.d);
    TEXT(",");
    NUMBER("total", u->limit.traffic.total);
    TEXT("},\"bandwidth\":{");
    NUMBER("u", u->limit.bandwidth.u);
    TEXT(",");
    NUMBER("d", u->limit.bandwidth.d);
    TEXT("},");
    NUMBER("ips", u->limit.ips);
    TEXT(",");
    NUMBER("devices", u->limit.devices);
    TEXT(",");
    NUMBER("cons_in", u->limit.cons_in);
    TEXT(",");
    NUMBER("cons_out", u->limit.cons_out);
    TEXT("},\"time\":{");
    NUMBER("created_at_ms", u->timeinfo.created_at_ms);
    TEXT(",");
    NUMBER("expire_at_ms", u->timeinfo.expire_at_ms);
    TEXT(",");
    NUMBER("expire_after_first_usage_ms", u->timeinfo.expire_after_first_usage_ms);
    TEXT(",");
    NUMBER("first_usage_at_ms", u->timeinfo.first_usage_at_ms);
    TEXT("},\"usage\":{");
    NUMBER("u", u->usage.u);
    TEXT(",");
    NUMBER("d", u->usage.d);
    TEXT("}}}");
#undef STRING
#undef NUMBER
#undef TEXT
}

api_result_t authenticationserverApiGetUser(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    authenticationserver_api_request_t request;
    const char *error = authenticationserverApiParse(message, context, kAuthenticationServerApiGetUser, &request);
    if (error != NULL)
        return authenticationserverApiError(context, error);
    authenticationserver_user_view_t view;
    error =
        authenticationserverCopyUserView(t, request.id, context->working_memory_allowance, context->deadline_ms, &view);
    if (error != NULL)
        return authenticationserverApiError(context, error);
    api_result_t result = authenticationserverApiRender(context,
                                                        kAuthenticationServerApiBodyCap,
                                                        kAuthenticationServerApiScratchCharge + sizeof(view) +
                                                            view.user.owned_string_bytes,
                                                        detail,
                                                        &view);
    userPublicDetailDestroy(&view.user);
    if (result.buffer == NULL)
        return authenticationserverApiError(
            context, authenticationserverApiExpired(context->deadline_ms) ? "timeout" : "record_too_large");
    return result;
}
