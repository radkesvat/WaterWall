#include "packet_batch.h"

#include "wdef.h"
#include <assert.h>
#include <stddef.h>

static thread_local packet_batch_t *current_packet_batch;
static thread_local bool            ending_packet_batch;

void packetBatchBegin(packet_batch_t *batch)
{
    assert(batch != NULL && current_packet_batch == NULL && ! ending_packet_batch);
    *batch               = (packet_batch_t) {0};
    current_packet_batch = batch;
}

bool packetBatchJoin(packet_batch_participant_t *participant)
{
    if (current_packet_batch == NULL)
        return false;
    assert(participant != NULL && participant->begin != NULL && participant->end != NULL);
    if (participant->batch == current_packet_batch)
        return false;
    assert(participant->batch == NULL);
    participant->batch                 = current_packet_batch;
    participant->next                  = current_packet_batch->participants;
    current_packet_batch->participants = participant;
    participant->begin(participant->context);
    return true;
}

void packetBatchEnd(packet_batch_t *batch)
{
    assert(batch != NULL && current_packet_batch == batch && ! ending_packet_batch);
    current_packet_batch                    = NULL;
    ending_packet_batch                     = true;
    packet_batch_participant_t *participant = batch->participants;
    batch->participants                     = NULL;
    for (packet_batch_participant_t *entry = participant; entry != NULL; entry = entry->next)
        entry->batch = NULL;
    while (participant != NULL)
    {
        packet_batch_participant_t *next = participant->next;
        participant->next                = NULL;
        participant->end(participant->context);
        participant = next;
    }
    ending_packet_batch = false;
}
