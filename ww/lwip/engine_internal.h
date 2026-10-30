#pragma once

#include "engine.h"

enum ww_lwip_state_module
{
#define WW_LWIP_MODULE(name) kWwLwipState_##name,
#include "engine_modules.inc"
#undef WW_LWIP_MODULE
    kWwLwipState_tcp_lists,
    kWwLwipStateCount
};

/* Private compiled-module state. All storage is reserved before publication. */
void *wwLwipModuleState(enum ww_lwip_state_module module);
void *wwLwipTimeoutAlloc(void);
void  wwLwipTimeoutFree(void *timeout);

#define WW_LWIP_MODULE(name)                                                                                           \
    size_t wwLwipStateSize_##name(void);                                                                               \
    void   wwLwipStateInit_##name(void *storage);
#include "engine_modules.inc"
#undef WW_LWIP_MODULE

bool wwLwipEngineIsReleasing(void);

/* Owner-only protocol bookkeeping. Does not consume or return receive credit. */
uint32_t wwLwipTcpReceiveWindow(struct tcp_pcb *pcb);
void     wwLwipTcpPrepareReceiveWindow(struct tcp_pcb *pcb);
void     wwLwipEngineForgetReceive(struct tcp_pcb *pcb);

void wwLwipNetifProtocolCleanup(struct netif *netif);
void wwLwipLowpanCleanup(void);
