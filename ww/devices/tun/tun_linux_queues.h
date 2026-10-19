#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Called before interface activation, only for a newly-created interface whose
 * first descriptor is exclusively owned by this device. out_fds has room for
 * requested_count descriptors. The first descriptor remains caller-owned on
 * every result. Extra descriptors are owned by the caller only on success.
 *
 * Returns requested_count after installing stable steering and attaching every
 * queue, or 1 after closing all extra descriptors. A fallback sets out_reason
 * and errno; requesting one queue sets out_reason to NULL. No live reconfiguration
 * is supported. The fixed queue set must survive until all readers and writers
 * have quiesced. */
uint16_t tunLinuxQueuesOpen(int first_fd, const char *name, bool checksum_setup, uint16_t requested_count, int *out_fds,
                            const char **out_reason);
