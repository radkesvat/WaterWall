#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Called before interface activation, only for a newly-created interface whose
 * first descriptor is exclusively owned by this device. out_fds has room for
 * requested_count descriptors. The first descriptor remains caller-owned on
 * every result. Extra descriptors are owned by the caller only on success.
 *
 * Returns requested_count after installing fixed steering and attaching every
 * queue. TCP/UDP uses flow affinity; complete opaque IPv4 uses an interface-local
 * per-CPU cursor for approximate round robin, without atomic updates; fragments
 * retain address/protocol affinity.
 * Returns 1 after closing all extra descriptors on fallback, including when the
 * kernel refuses the per-CPU map or steering program. A fallback sets out_reason
 * and errno; requesting one queue sets out_reason to NULL. No live reconfiguration
 * is supported. The fixed queue set must survive until all readers and writers
 * have quiesced. */
uint16_t tunLinuxQueuesOpen(int first_fd, const char *name, bool checksum_setup, uint16_t requested_count, int *out_fds,
                            const char **out_reason);
