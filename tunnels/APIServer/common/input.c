#include "APIServer/structure.h"

void apiserverReleaseRequest(apiserver_lstate_t *ls)
{
    api_request_t *request = ls->requests;
    assert(request != NULL && ls->input_bytes >= request->wire_size);
    assert(ls->request_wire_bytes >= request->wire_size);
    ls->requests = request->next;
    if (! ls->requests)
        ls->requests_tail = NULL;
    --ls->request_count;
    ls->input_bytes -= request->wire_size;
    ls->request_wire_bytes -= request->wire_size;
    apiserverRelease(ls, request->charge);
    apiserverRequestClear(request);
    memoryFree(request);
}

static void appendRequest(apiserver_lstate_t *ls, api_request_t *r)
{
    if (ls->requests_tail)
        ls->requests_tail->next = r;
    else
        ls->requests = r;
    ls->requests_tail = r;
    ++ls->request_count;
    assert(r->wire_size <= ls->input_bytes - ls->request_wire_bytes);
    ls->request_wire_bytes += r->wire_size;
}

bool apiserverFramingError(apiserver_lstate_t *ls, const char *error)
{
    /* The error is only publishable at the head; otherwise closure preserves FIFO. */
    if (ls->requests || ls->output || ! apiserverReserve(ls, sizeof(api_request_t)))
        return false;
    api_request_t *r = memoryAllocateZero(sizeof(*r));
    r->charge        = sizeof(*r);
    r->error         = error;
    r->close         = true;
    r->wire_size     = ls->header_size;
    appendRequest(ls, r);
    ls->header_size    = 0;
    ls->frame_deadline = 0;
    return true;
}

static void consumeInput(apiserver_lstate_t *ls, size_t amount)
{
    api_input_t *input = ls->input_head;
    memorySecureZero(sbufGetMutablePtr(input->buffer), amount);
    sbufShiftRight(input->buffer, (uint32_t) amount);
    if (sbufGetLength(input->buffer) == 0)
    {
        ls->input_head = input->next;
        if (! ls->input_head)
            ls->input_tail = NULL;
        --ls->input_fragments;
        lineReuseBuffer(ls->line, input->buffer);
        apiserverRelease(ls, input->charge);
        memoryFree(input);
    }
}

/* Charge both allocations until copying has retired the older storage. */
static bool growFrame(apiserver_lstate_t *ls, size_t needed)
{
    if (needed <= ls->frame_capacity)
        return true;
    size_t       capacity = ls->frame_capacity ? ls->frame_capacity : 1024;
    const size_t maximum  = ls->frame_size + 1;
    if (capacity > maximum)
        capacity = maximum;
    while (capacity < needed)
        capacity = capacity > maximum / 2 ? maximum : capacity * 2;
    if (! apiserverReserve(ls, capacity))
        return false;
    char *frame = memoryAllocate(capacity);
    if (ls->frame_used)
    {
        memcpy(frame, ls->frame, ls->frame_used);
        memorySecureZero(ls->frame, ls->frame_used);
    }
    memoryFree(ls->frame);
    apiserverRelease(ls, ls->frame_capacity);
    ls->frame          = frame;
    ls->frame_capacity = capacity;
    return true;
}

bool apiserverParseInput(apiserver_lstate_t *ls)
{
    apiserver_tstate_t *ts     = tunnelGetState(ls->tunnel);
    size_t              bytes  = 0;
    unsigned            frames = 0;
    while (ls->input_head && bytes < kApiTurnBytes && frames < kApiTurnFrames &&
           ls->request_count < ts->limits.max_queued_requests + 1 && ! (ls->requests_tail && ls->requests_tail->close))
    {
        api_input_t *input = ls->input_head;
        if (ls->header_size == 0 && ! ls->frame)
            ls->frame_deadline = input->received_ms + ts->limits.frame_timeout_ms;
        if (nodeApiNowMs() >= ls->frame_deadline)
            return apiserverFramingError(ls, "timeout");
        size_t n = sbufGetLength(input->buffer);
        if (n > kApiTurnBytes - bytes)
            n = kApiTurnBytes - bytes;
        if (ls->header_size < 4)
        {
            if (n > 4 - ls->header_size)
                n = 4 - ls->header_size;
            memcpy(ls->header + ls->header_size, sbufGetRawPtr(input->buffer), n);
            ls->header_size += n;
            consumeInput(ls, n);
            bytes += n;
            if (ls->header_size != 4)
                continue;
            ls->frame_size = ((uint32_t) ls->header[0] << 24) | ((uint32_t) ls->header[1] << 16) |
                             ((uint32_t) ls->header[2] << 8) | ls->header[3];
            if (! ls->frame_size || ls->frame_size > ts->limits.max_request_envelope)
                return apiserverFramingError(ls, "invalid_request");
            continue;
        }
        if (n > ls->frame_size - ls->frame_used)
            n = ls->frame_size - ls->frame_used;
        if (! growFrame(ls, ls->frame_used + n + 1))
            return false;
        memcpy(ls->frame + ls->frame_used, sbufGetRawPtr(input->buffer), n);
        ls->frame_used += n;
        consumeInput(ls, n);
        bytes += n;
        if (ls->frame_used != ls->frame_size)
            continue;
        ls->frame[ls->frame_size] = '\0';
        size_t owned_charge       = sizeof(api_request_t) + ls->frame_size + 1;
        size_t temporary_charge   = ls->frame_size + 8192;
        if (! apiserverReserve(ls, owned_charge + temporary_charge))
            return false;
        api_request_t *r = memoryAllocateZero(sizeof(*r));
        r->charge        = owned_charge;
        r->wire_size     = ls->frame_size + 4;
        r->deadline_ms   = nodeApiNowMs() + ts->limits.request_timeout_ms;
        apiserverRequestParse(r, ls->frame, ls->frame_size);
        apiserverRelease(ls, temporary_charge);
        appendRequest(ls, r);
        memorySecureZero(ls->frame, ls->frame_used);
        memoryFree(ls->frame);
        apiserverRelease(ls, ls->frame_capacity);
        ls->frame          = NULL;
        ls->frame_size     = 0;
        ls->frame_capacity = 0;
        ls->frame_used     = 0;
        ls->header_size    = 0;
        ls->frame_deadline = 0;
        ++frames;
    }
    return true;
}
