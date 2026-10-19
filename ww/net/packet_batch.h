#pragma once

#include <stdbool.h>

typedef struct packet_batch_s packet_batch_t;
typedef void (*PacketBatchCallback)(void *context);

/* Owner-local, persistent participant. Zero-initialize the complete object,
 * then assign callbacks/context before use;
 * keep this object and its context alive until the enclosing End returns.
 * Fields next/batch are private to the scope implementation. */
typedef struct packet_batch_participant_s
{
    struct packet_batch_participant_s *next;
    packet_batch_t                    *batch;
    PacketBatchCallback                begin;
    PacketBatchCallback                end;
    void                              *context;
} packet_batch_participant_t;

/* Stack-owned synchronous boundary on one event worker. Do not nest scopes,
 * yield, copy an active scope, or change worker context between Begin/End.
 * The caller bounds the delivery quantum and ends every scope on every exit.
 * Opening a scope alone invokes no participant callbacks. */
struct packet_batch_s
{
    packet_batch_participant_t *participants;
};

void packetBatchBegin(packet_batch_t *batch);
void packetBatchEnd(packet_batch_t *batch);

/* Join from the participant's owner before entering its subsystem. Returns
 * true only for the first join in this scope; false outside a scope or for a
 * repeated join. Begin runs immediately and End runs once at the boundary.
 * Callbacks cannot yield or open another scope. End clears all memberships
 * before invoking callbacks; joins from flush callbacks have no active scope. */
bool packetBatchJoin(packet_batch_participant_t *participant);
