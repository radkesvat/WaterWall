#include "AuthenticationServer/api.h"

static void bytes(authenticationserver_json_writer_t *w, const char *text, size_t length)
{
    if (w->overflow || w->timeout)
        return;
    if (authenticationserverApiExpired(w->deadline_ms))
    {
        w->timeout = true;
        return;
    }
    if (length > w->capacity - w->used)
    {
        w->overflow = true;
        return;
    }
    if (w->output != NULL)
        memoryCopy(w->output + w->used, text, length);
    w->used += length;
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
        const unsigned char c = (unsigned char) text[i++];
        if (c == '"' || c == '\\')
        {
            const char escaped[] = {'\\', (char) c};
            bytes(w, escaped, sizeof(escaped));
        }
        else if (c < 0x20)
        {
            const char escaped[] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
            bytes(w, escaped, sizeof(escaped));
        }
        else
            bytes(w, (const char *) &c, 1);
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
    sbuf_t *buffer  = bufferpoolGetBestFit(pool, (uint32_t) writer.used, 0);
    writer.output   = (char *) sbufGetMutablePtr(buffer);
    size_t measured = writer.used;
    writer.used     = 0;
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
