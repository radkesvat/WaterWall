#pragma once

#include "wwapi.h"

typedef struct vmess_replay_s vmess_replay_t;

vmess_replay_t *vmessReplayCreate(size_t capacity);
bool            vmessReplaySnapshot(vmess_replay_t *replay, uint64_t *auth, uint64_t *session);
void            vmessReplayDestroy(vmess_replay_t *replay);
/* Atomic admission of both marks. wall_seconds and monotonic_ms are separate
 * clocks; no borrowed account data survives this call. Refusal changes no mark. */
bool vmessReplayAdmit(vmess_replay_t *replay, const uint8_t auth_id[16], const uint8_t uuid[16], const uint8_t key[16],
                      const uint8_t iv[16], uint64_t timestamp, uint64_t wall_seconds, uint64_t monotonic_ms);
