#include "devices/device_pool.h"
#include "global_state.h"

buffer_pool_t *devicePoolCreate(buffer_pool_t *worker_pool, uint32_t minimum_small)
{
    assert(worker_pool != NULL);
    return bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
                            GSTATE.masterpool_buffer_pools_medium,
                            GSTATE.masterpool_buffer_pools_small,
                            PROPER_BUFFER_POOL_WIDTH(RAM_PROFILE),
                            bufferpoolGetLargeBufferSize(worker_pool),
                            bufferpoolGetMediumBufferSize(worker_pool),
                            max(bufferpoolGetSmallBufferSize(worker_pool), minimum_small),
                            bufferpoolGetSplicePayloadLimit(worker_pool),
                            bufferpoolGetWaitingBudgetBasis(worker_pool));
}

void devicePoolUpdatePadding(buffer_pool_t *device_pool, buffer_pool_t *worker_pool)
{
    assert(device_pool != NULL && worker_pool != NULL);
    bufferpoolUpdateAllocationPaddings(device_pool,
                                       bufferpoolGetLargeBufferPadding(worker_pool),
                                       bufferpoolGetMediumBufferPadding(worker_pool),
                                       bufferpoolGetSmallBufferPadding(worker_pool),
                                       bufferpoolGetSpliceBufferPadding(worker_pool));
}
