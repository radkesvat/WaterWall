#include "AuthenticationServer/api.h"
#include "AuthenticationServer/edit_token.h"

static void bytes(authenticationserver_json_writer_t *w, const char *text, size_t length)
{
    if (w->overflow || w->timeout)
        return;
    if (length > w->capacity - w->used)
    {
        w->overflow = true;
        return;
    }
    do
    {
        if (! w->clock_checked || w->used - w->checked_at >= 256)
        {
            w->clock_checked = true;
            w->checked_at    = w->used;
            if (authenticationserverApiExpired(w->deadline_ms))
            {
                w->timeout = true;
                return;
            }
        }
        const size_t chunk = min(length, 256 - (w->used - w->checked_at));
        if (w->output != NULL && chunk != 0)
            memoryCopy(w->output + w->used, text, chunk);
        w->used += chunk;
        text += chunk;
        length -= chunk;
    } while (length != 0);
}

void authenticationserverJsonText(authenticationserver_json_writer_t *w, const char *text)
{
    bytes(w, text, strlen(text));
}

/* Only owned, bounded, validated public strings reach the renderer. Rendering
 * directly into its final buffer avoids a second body-sized scratch allocation. */
void authenticationserverJsonString(authenticationserver_json_writer_t *w, const char *text)
{
    static const char hex[] = "0123456789abcdef";
    bytes(w, "\"", 1);
    size_t i = 0;
    while (! w->overflow && ! w->timeout && text[i] != '\0')
    {
        const size_t start = i;
        while ((unsigned char) text[i] >= 0x20 && text[i] != '"' && text[i] != '\\')
            ++i;
        if (i != start)
            bytes(w, text + start, i - start);
        if (text[i] == '\0' || w->overflow || w->timeout)
            break;
        const unsigned char c = (unsigned char) text[i++];
        if (c == '"' || c == '\\')
        {
            const char escaped[] = {'\\', (char) c};
            bytes(w, escaped, sizeof(escaped));
        }
        else
        {
            const char escaped[] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
            bytes(w, escaped, sizeof(escaped));
        }
    }
    bytes(w, "\"", 1);
}

void authenticationserverJsonU64(authenticationserver_json_writer_t *w, uint64_t value)
{
    char text[24];
    int  length = snprintf(text, sizeof(text), "\"%" PRIu64 "\"", value);
    assert(length > 0 && (size_t) length < sizeof(text));
    bytes(w, text, (size_t) length);
}

static api_result_t errorBody(const node_api_call_context_t *context, const char *code)
{
    char text[96];
    int  length = snprintf(text, sizeof(text), "{\"error\":{\"code\":\"%s\"}}", code);
    assert(length > 0 && (size_t) length < sizeof(text));
    buffer_pool_t    *pool = getCurrentEventWorkerBufferPool();
    buffer_pool_fit_t fit;
    if ((size_t) length > context->max_response_body_size || ! bufferpoolQueryBestFit(pool, (size_t) length, 0, &fit) ||
        context->working_memory_allowance < kAuthenticationServerApiScratchCharge ||
        fit.allocation_charge > context->working_memory_allowance - kAuthenticationServerApiScratchCharge)
        return (api_result_t) {.result_code = kApiResultError};
    sbuf_t *buffer = bufferpoolGetBestFit(pool, (uint32_t) length, 0);
    sbufSetLength(buffer, (uint32_t) length);
    memoryCopy(sbufGetMutablePtr(buffer), text, (size_t) length);
    return (api_result_t) {.result_code = kApiResultError, .buffer = buffer};
}

api_result_t authenticationserverApiError(const node_api_call_context_t *context, const char *code)
{
    return errorBody(context, code);
}

api_result_t authenticationserverApiRender(const node_api_call_context_t *context, size_t body_cap,
                                           size_t retained_charge, authenticationserver_api_render_fn render,
                                           const void *view)
{
    const size_t                       cap    = min(body_cap, context->max_response_body_size);
    authenticationserver_json_writer_t writer = {.capacity = cap, .deadline_ms = context->deadline_ms};
    render(&writer, view);
    if (writer.timeout)
        return (api_result_t) {.result_code = kApiResultError};
    buffer_pool_fit_t fit;
    buffer_pool_t    *pool = getCurrentEventWorkerBufferPool();
    if (writer.overflow || ! bufferpoolQueryBestFit(pool, writer.used, 0, &fit) ||
        retained_charge > context->working_memory_allowance ||
        fit.allocation_charge > context->working_memory_allowance - retained_charge)
    {
        /* Caller releases retained snapshots before creating any error body. */
        return (api_result_t) {.result_code = kApiResultError};
    }
    return authenticationserverApiRenderMeasured(context, retained_charge, writer.used, render, view);
}

api_result_t authenticationserverApiRenderMeasured(const node_api_call_context_t *context, size_t retained_charge,
                                                   size_t measured, authenticationserver_api_render_fn render,
                                                   const void *view)
{
    buffer_pool_t    *pool = getCurrentEventWorkerBufferPool();
    buffer_pool_fit_t fit;
    if (! bufferpoolQueryBestFit(pool, measured, 0, &fit) || retained_charge > context->working_memory_allowance ||
        fit.allocation_charge > context->working_memory_allowance - retained_charge)
        return (api_result_t) {.result_code = kApiResultError};
    sbuf_t                            *buffer = bufferpoolGetBestFit(pool, (uint32_t) measured, 0);
    authenticationserver_json_writer_t writer = {
        .output = (char *) sbufGetMutablePtr(buffer), .capacity = measured, .deadline_ms = context->deadline_ms};
    render(&writer, view);
    if (writer.timeout || authenticationserverApiExpired(context->deadline_ms))
    {
        bufferpoolReuseBuffer(pool, buffer);
        return (api_result_t) {.result_code = kApiResultError};
    }
    assert(! writer.overflow && writer.used == measured);
    sbufSetLength(buffer, (uint32_t) measured);
    return (api_result_t) {.result_code = kApiResultOk, .buffer = buffer};
}

const char *authenticationserverApiPrepareAck(sbuf_t *buffer, size_t capacity, uint64_t deadline, uint64_t id,
                                              const uint8_t instance[16], uint64_t revision)
{
    char token[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(instance, revision, token);
    authenticationserver_json_writer_t w = {
        .output = (char *) sbufGetMutablePtr(buffer), .capacity = capacity, .deadline_ms = deadline};
    authenticationserverJsonText(&w, "{\"id\":");
    authenticationserverJsonU64(&w, id);
    authenticationserverJsonText(&w, ",\"config_revision\":");
    authenticationserverJsonU64(&w, revision);
    authenticationserverJsonText(&w, ",\"edit_token\":");
    authenticationserverJsonString(&w, token);
    authenticationserverJsonText(&w, "}");
    if (w.timeout || authenticationserverApiExpired(deadline))
        return "timeout";
    if (w.overflow)
        return "response_too_large";
    sbufSetLength(buffer, (uint32_t) w.used);
    return NULL;
}
