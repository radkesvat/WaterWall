#pragma once

enum
{
    kWorkerMessageDrainBatchSize = 256,
};

static_assert(kWorkerMessageDrainBatchSize > 0 && kWorkerMessageDrainBatchSize <= 1024,
              "worker-message drain batch size must remain bounded");
