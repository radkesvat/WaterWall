#include "APIServer/structure.h"

bool apiserverPublishResponse(apiserver_lstate_t *ls, const char *error, const node_api_operation_t *op,
                              enum api_result_e code, const uint8_t *body, size_t body_size)
{
    apiserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    assert(ls->output == NULL && ls->requests != NULL);
    size_t length = apiserverResponseSize(ls->requests->id, error, op, code, body, body_size);
    if (length == SIZE_MAX || length > ts->limits.max_response_envelope)
    {
        error  = "response_too_large";
        length = apiserverResponseSize(ls->requests->id, error, NULL, kApiResultError, NULL, 0);
    }
    if (length > ts->limits.max_response_envelope || length > UINT32_MAX || length > SIZE_MAX - 4 ||
        ! apiserverReserve(ls, length + 4))
        return false;
    ls->output_size = length + 4;
    ls->output      = memoryAllocate(ls->output_size);
    ls->output[0]   = (uint8_t) (length >> 24);
    ls->output[1]   = (uint8_t) (length >> 16);
    ls->output[2]   = (uint8_t) (length >> 8);
    ls->output[3]   = (uint8_t) length;
    apiserverResponseWrite((char *) ls->output + 4, ls->requests->id, error, op, code, body, body_size);
    /* Request and output windows are separate, including during transport Pause. */
    ls->requests->deadline_ms = 0;
    ls->output_deadline       = nodeApiNowMs() + ts->limits.output_timeout_ms;
    ls->close_after_output    = ls->requests->close || (error && strcmp(error, "timeout") == 0);
    return true;
}
