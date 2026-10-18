#include "APIServer/structure.h"

void apiserverUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    apiserver_lstate_t *ls = lineGetState(line, t);
    apiserver_tstate_t *ts = tunnelGetState(t);
    assert(ls->tunnel == t);
    assert(! sbufIsSplice(payload)); /* APIServer blocks splice for the entire chain. */
    size_t bytes = sbufGetLength(payload);
    /* Admitted callbacks and synchronous shutdown flushes can still deliver bytes. */
    if (ls->quiesced || atomic_load(&ts->stopping))
    {
        lineReuseBuffer(line, payload);
        return;
    }
    if (! bytes)
    {
        lineReuseBuffer(line, payload);
        return;
    }
    size_t charge = sbufGetAllocationCharge(payload);
    if (charge > SIZE_MAX - sizeof(api_input_t) || bytes > ts->limits.max_input_bytes - ls->input_bytes ||
        ls->input_fragments >= ts->limits.max_input_fragments || ! apiserverReserve(ls, charge + sizeof(api_input_t)))
    {
        lineReuseBuffer(line, payload);
        apiserverCloseSession(t, line);
        return;
    }
    api_input_t *input = memoryAllocateZero(sizeof(*input));
    input->buffer      = payload;
    input->charge      = charge + sizeof(*input);
    input->received_ms = nodeApiNowMs();
    if (ls->input_tail)
        ls->input_tail->next = input;
    else
        ls->input_head = input;
    ls->input_tail = input;
    ls->input_bytes += bytes;
    ++ls->input_fragments;
    ls->idle_deadline = input->received_ms + ts->limits.idle_timeout_ms;
    apiserverProgress(t, line);
}
