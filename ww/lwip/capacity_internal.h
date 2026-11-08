#pragma once

#include "capacity.h"

struct memp_desc;
struct ww_lwip_slab_s;

typedef struct ww_lwip_pool_state_s
{
    struct ww_lwip_pool_state_s *next;
    const struct memp_desc      *descriptor;
    struct ww_lwip_slab_s       *slabs;
    struct ww_lwip_slab_s       *available;
    uint32_t                     limit;
    uint32_t                     allocated;
    uint32_t                     recovery_allocated;
    uint32_t                     held;
    uint32_t                     peak_held;
    uint64_t                     entry_refusals;
    uint64_t                     byte_refusals;
    uint64_t                     reserved_bytes;
    bool                         rx;
} ww_lwip_pool_state_t;

void  wwLwipCapacityInitialize(void);
void  wwLwipCapacityCleanup(void);
void  wwLwipCapacityPoolInitialize(const struct memp_desc *pool);
void  wwLwipCapacityRegisterRxPool(const struct memp_desc *pool);
void *wwLwipCapacityMalloc(const struct memp_desc *pool);
void  wwLwipCapacityFree(const struct memp_desc *pool, void *item);
/* Caller holds shared allocator protection. */
bool wwLwipCapacityHasFree(const struct memp_desc *pool);
bool wwLwipCapacityIsRecovery(const void *item);
bool wwLwipCapacityRecoveryActive(void);
/* Private synchronous allocation scope: surrounds only TCP control pbuf
 * construction, never stack input, protocol callbacks or application writes. */
void wwLwipCapacityRecoveryBegin(void);
void wwLwipCapacityRecoveryEnd(void);
