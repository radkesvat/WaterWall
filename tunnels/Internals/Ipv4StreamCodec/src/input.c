#include "Ipv4StreamCodec/input.h"

void ipv4streamInputInit(ipv4stream_input_t *input)
{
    *input = (ipv4stream_input_t) {0};
    bufferqueueInitEmpty(&input->pending);
    bufferbudgetInit(&input->budget,
                     (buffer_budget_cost_t) {.bytes = kIpv4StreamNestedBytes, .charge = kIpv4StreamNestedCharge});
    const bool attached = bufferqueueTryAttachBudget(&input->pending, &input->budget);
    assert(attached);
    discard attached;
}

void ipv4streamInputDestroy(ipv4stream_input_t *input)
{
    bufferqueueDestroy(&input->pending);
    bufferbudgetReservationRelease(&input->active);
    bufferbudgetAssertEmpty(&input->budget);
    input->draining = false;
}

void ipv4streamInputReset(ipv4stream_input_t *input)
{
    ipv4streamInputDestroy(input);
    ipv4streamInputInit(input);
}

ipv4stream_input_result_t ipv4streamInputAdmit(ipv4stream_input_t *input, buffer_stream_t *stream, sbuf_t *buf)
{
    assert(stream->pool != NULL && ! sbufIsSplice(buf));
    if (sbufGetLength(buf) == 0)
    {
        bufferpoolReuseBuffer(stream->pool, buf);
        return kIpv4StreamInputEmpty;
    }
    if (input->draining)
        return bufferqueueTryPushBack(&input->pending, &buf) ? kIpv4StreamInputQueued : kIpv4StreamInputRejected;

    assert(bufferqueueGetBufCount(&input->pending) == 0 && input->active.budget == NULL);
    if (bufferstreamGetBufLen(stream) > UINT32_MAX - sbufGetLength(buf))
        return kIpv4StreamInputRejected;
    input->draining = true;
    bufferstreamPush(stream, buf);
    return kIpv4StreamInputDrain;
}

bool ipv4streamInputAdvance(ipv4stream_input_t *input, buffer_stream_t *stream)
{
    assert(input->draining);
    assert(bufferstreamGetBufLen(stream) < kMaxAllowedPacketLength);
    const bool settled = bufferstreamSettleRetained(stream, kIpv4StreamIncompleteCharge);
    assert(settled);
    discard settled;
    bufferbudgetReservationRelease(&input->active);
    sbuf_t *next = bufferqueuePopFrontReserved(&input->pending, &input->active);
    if (next != NULL)
    {
        bufferstreamPush(stream, next);
        return true;
    }
    input->draining = false;
    return false;
}
