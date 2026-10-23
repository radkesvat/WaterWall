#include "APIServer/structure.h"

bool apiserverPublishResponse(apiserver_lstate_t *ls, const char *error, const node_api_operation_t *op,
                              enum api_result_e code, const uint8_t *body, size_t body_size)
{
    apiserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    assert(ls->output == NULL && ls->requests != NULL);
    size_t                 length;
    api_response_measure_t measured =
        apiserverResponseMeasure(ls->requests->id, error, op, code, body, body_size, &length);
    if (measured != kApiResponseValid || length > ts->limits.max_response_envelope)
    {
        error  = measured == kApiResponseInvalid ? "invalid_response" : "response_too_large";
        length = apiserverResponseSize(ls->requests->id, error, NULL, kApiResultError, NULL, 0);
    }
    /* The bounded fallback error fits even the minimum configured envelope. */
    assert(length <= ts->limits.max_response_envelope && length <= UINT32_MAX && length <= SIZE_MAX - 4);
    if (! apiserverReserve(ls, length + 4))
        return false;
    ls->output_size = length + 4;
    ls->output      = memoryAllocate(ls->output_size);
    ls->output[0]   = (uint8_t) (length >> 24);
    ls->output[1]   = (uint8_t) (length >> 16);
    ls->output[2]   = (uint8_t) (length >> 8);
    ls->output[3]   = (uint8_t) length;
    apiserverResponseWrite((char *) ls->output + 4, ls->requests->id, error, op, code, body, body_size);
    const uint64_t now = nodeApiNowMs();
    if (ls->requests->deadline_ms && now >= ls->requests->deadline_ms && (! error || strcmp(error, "timeout") != 0))
    {
        /* Encoding is part of the request window. Nothing has reached the
         * transport yet, so replace the late result with one closing timeout.
         * A committed handler mutation remains committed. */
        memorySecureZero(ls->output, ls->output_size);
        memoryFree(ls->output);
        apiserverRelease(ls, ls->output_size);
        ls->output      = NULL;
        ls->output_size = 0;
        return apiserverPublishResponse(ls, "timeout", NULL, kApiResultError, NULL, 0);
    }
    /* Request and output windows are separate, including during transport Pause. */
    ls->requests->deadline_ms = 0;
    ls->output_deadline       = now + ts->limits.output_timeout_ms;
    ls->close_after_output    = ls->requests->close || (error && strcmp(error, "timeout") == 0);
    return true;
}
