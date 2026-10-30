#pragma once

#include "buffer_queue.h"
#include "buffer_stream.h"

enum
{
    kIpv4StreamNestedBytes      = 128U * 1024U,
    kIpv4StreamNestedCharge     = 2U * 1024U * 1024U,
    kIpv4StreamNestedEntries    = 1024,
    kIpv4StreamIncompleteCharge = 128U * 1024U
};

/* Stable, owner-worker storage. The current outer delivery is processed
 * synchronously; only additional nested deliveries use this bounded FIFO.
 * A popped nested delivery keeps its reservation until its complete packets
 * have been consumed. No tunnel callbacks or line lifetime decisions occur here. */
typedef struct ipv4stream_input_s
{
    buffer_queue_t              pending;
    buffer_budget_t             budget;
    buffer_budget_reservation_t active;
    bool                        draining;
} ipv4stream_input_t;

typedef enum ipv4stream_input_result_e
{
    kIpv4StreamInputDrain,
    kIpv4StreamInputQueued,
    kIpv4StreamInputEmpty,
    kIpv4StreamInputRejected
} ipv4stream_input_result_t;

void ipv4streamInputInit(ipv4stream_input_t *input);
void ipv4streamInputDestroy(ipv4stream_input_t *input);
void ipv4streamInputReset(ipv4stream_input_t *input);

/* Takes buf except on Rejected. Empty input is recycled. Drain begins the
 * caller-owned extraction loop; Queued must return to the existing drain. */
ipv4stream_input_result_t ipv4streamInputAdmit(ipv4stream_input_t *input, buffer_stream_t *stream, sbuf_t *buf);

/* Call only after extraction needs more bytes, and after validating all callback
 * lifetime/association changes. Compacts incomplete storage and advances one
 * queued delivery. False finishes the drain and clears draining. */
bool ipv4streamInputAdvance(ipv4stream_input_t *input, buffer_stream_t *stream);
