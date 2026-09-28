#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct wloop_s;
struct netif;
struct pbuf;
typedef struct ww_lwip_engine_s ww_lwip_engine_t;
typedef void (*ww_lwip_wake_fn)(ww_lwip_engine_t *engine, void *argument);

/* Startup and finalization are exclusive; no worker may use shared storage then. */
void wwLwipEngineSharedInit(void);
void wwLwipEngineSharedCleanup(void);

/* The runtime owns engines. Creation, entry, dispatch and destruction require the owner. */
ww_lwip_engine_t *wwLwipEngineCreate(uint8_t owner, struct wloop_s *loop);
void              wwLwipEngineDestroy(ww_lwip_engine_t *engine);
bool              wwLwipEngineEnter(ww_lwip_engine_t *engine, ww_lwip_engine_t **previous);
void              wwLwipEngineLeave(ww_lwip_engine_t *engine, ww_lwip_engine_t *previous);
ww_lwip_engine_t *wwLwipEngineCurrent(void);
void              wwLwipEngineAssertCurrent(void);
bool              wwLwipEngineOwnsNetif(const struct netif *netif);
int               wwLwipEngineInput(ww_lwip_engine_t *engine, struct pbuf *packet, struct netif *netif);
void              wwLwipEngineCheckTimeouts(ww_lwip_engine_t *engine);
size_t            wwLwipEngineControlSize(void);
uint32_t          wwLwipEngineNextTimeout(ww_lwip_engine_t *engine);
void              wwLwipEngineSetWake(ww_lwip_engine_t *engine, ww_lwip_wake_fn wake, void *argument);
void              wwLwipEngineQuiesce(ww_lwip_engine_t *engine);

/* Implemented by the worker runtime; context selection never grants ownership. */
bool wwLwipEngineOwnerIsCurrent(uint8_t owner, const struct wloop_s *loop);
