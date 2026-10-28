#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct wloop_s;
struct netif;
struct pbuf;
struct tcp_pcb;
typedef struct ww_lwip_engine_s ww_lwip_engine_t;
typedef void (*ww_lwip_wake_fn)(ww_lwip_engine_t *engine, void *argument);

#define WW_LWIP_DEFAULT_RECEIVE_BUDGET (32U * 1024U * 1024U)
#define WW_LWIP_MIN_RECEIVE_WINDOW     (64U * 1024U)

/* Exclusive startup, before shared initialization. Zero disables the adaptive
 * advertised-window target. Otherwise accepts 64 KiB through 1 GiB; each owner
 * engine shares this byte target
 * across network TCP connections, with a 64-KiB per-flow floor. Outstanding
 * advertisements and accepted data remain valid, so this is not a memory cap. */
void wwLwipEngineSetDefaultReceiveBudget(uint32_t budget);

/* Startup and finalization are exclusive; no worker may use shared storage then. */
void wwLwipEngineSharedInit(void);
void wwLwipEngineSharedCleanup(void);

/* The runtime owns engines. Creation, entry, dispatch and destruction require the owner.
 * Creation returns NULL before shared initialization or for a foreign owner; heap OOM is fatal. */
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

/* Owner-only bounded receive scopes, begun/ended outside stack entry or dispatch.
 * Calls do not retain an entered engine scope. End flushes ordinary cumulative
 * ACKs before returning. Do not nest batches or span an event-loop yield;
 * input, control and recovery ACK paths remain live. */
void wwLwipEngineBeginAckBatch(ww_lwip_engine_t *engine);
void wwLwipEngineEndAckBatch(ww_lwip_engine_t *engine);
/* Join the current generic receive quantum before stack entry. Returns true
 * only on first participation; no scope or an existing join returns false.
 * The engine remains alive through the synchronous receive boundary. */
bool wwLwipEngineJoinReceiveBatch(ww_lwip_engine_t *engine);

/* Return one accepted receive delivery's credit while its owner engine is
 * entered. Unlike tcp_recved(), this accepts the complete scaled-window amount
 * and evaluates window-update ACK policy once, without intermediate 16-bit
 * advertisements. It does not delay a required window update or open a batch. */
void wwLwipTcpRecved(struct tcp_pcb *pcb, uint32_t length);

/* Implemented by the worker runtime; context selection never grants ownership. */
bool wwLwipEngineOwnerIsCurrent(uint8_t owner, const struct wloop_s *loop);
