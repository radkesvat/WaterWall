#pragma once

/* Generated during CMake configuration. This private header is intentionally
 * not part of the public worker-message API or an installed tuning surface. */
#include "worker_message_batch_config.h"

enum
{
    kWorkerMessageDrainBatchSize = WW_WORKER_MESSAGE_EFFECTIVE_DRAIN_BATCH_SIZE,
};

static_assert(kWorkerMessageDrainBatchSize > 0 && kWorkerMessageDrainBatchSize <= 1024,
              "worker-message drain batch size must remain bounded");
