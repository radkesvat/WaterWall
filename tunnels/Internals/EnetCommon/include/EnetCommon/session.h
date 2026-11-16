#pragma once

#include "wwapi.h"

#include "EnetCommon/settings.h"

/*
 * One ENet session on one WaterWall worker.
 *
 * A session owns one EnetCommon driver, one worker timer, and the buffers that travel between the driver and the
 * node. The driver's sinks only stage; the session hands staged datagrams and stream bytes to the node after the
 * driver call has returned, so a neighbouring tunnel can never reenter ENet.
 *
 * Calls made from inside a callback are queued and run in order by the call that is already driving the session.
 * Every call for one session happens on its worker.
 */

typedef struct enet_session_s enet_session_t;

typedef enum enet_session_result_e
{
    kEnetSessionClosed,          /* the local close finished */
    kEnetSessionPeerClosed,      /* the peer disconnected, or it timed out */
    kEnetSessionAborted,         /* the owner aborted: the carrier finished or the worker is stopping */
    kEnetSessionDrainTimeout,    /* close-drain-timeout-ms expired before the peer confirmed the close */
    kEnetSessionConnectTimeout,  /* server: no native connection within no-recv-timeout-ms */
    kEnetSessionProtocolFailure, /* the peer broke the stream contract, or ENet failed */
    kEnetSessionCapacityFailure, /* the hard send cap or the nested-input budget refused data */
} enet_session_result_t;

typedef struct enet_session_config_s
{
    enet_settings_t settings;
    bool            client;            /* true sends the native connect request; false waits for one */
    buffer_pool_t  *pool;              /* owner worker's pool; outlives the session */
    wloop_t        *loop;              /* NULL permits deterministic explicit Tick calls */
    uint64_t (*now)(void *clock_user); /* NULL uses the loop's monotonic clock */
    void *clock_user;
} enet_session_config_t;

typedef struct enet_session_callbacks_s
{
    /* emit and payload transfer the entire buffer on every return. */
    void (*emit)(void *user, sbuf_t *packet);
    void (*payload)(void *user, sbuf_t *payload);
    /* The native handshake finished. Called once, before the first payload. */
    void (*connected)(void *user);
    /* The local send hold changed. The new state is published before the call. */
    void (*pressure)(void *user, bool paused);
    /* The session ended. Called once. It may release the owner's reference; destroy_user runs at final release. */
    void (*terminal)(void *user, enet_session_result_t result);
    void (*destroy_user)(void *user);
} enet_session_callbacks_t;

/* Create owns one reference. Returns NULL when ENet or the worker timer refuses the session. */
enet_session_t *enetSessionCreate(const enet_session_config_t *config, const enet_session_callbacks_t *callbacks,
                                  void *user);
void            enetSessionRetain(enet_session_t *session);
void            enetSessionRelease(enet_session_t *session);
/* Start after the neighbouring Init has safely returned. Nothing is emitted before it. */
void enetSessionStart(enet_session_t *session);
/* Send takes ownership of application bytes. They are dropped after AppFinish. */
void enetSessionSend(enet_session_t *session, sbuf_t *payload);
/* Input takes ownership of one carrier datagram. */
void enetSessionInput(enet_session_t *session, sbuf_t *packet);
/* The application finished: deliver what was accepted, then close. Ends with kEnetSessionClosed, or with
 * kEnetSessionDrainTimeout at the deadline. */
void enetSessionAppFinish(enet_session_t *session);
/* Ends the session now and runs the terminal callback before returning. Nothing is emitted. */
void enetSessionAbort(enet_session_t *session, enet_session_result_t result);
/* Runs protocol timers at the given time. The worker timer calls it; tests without a loop call it directly. */
void enetSessionTick(enet_session_t *session, uint64_t now);
/* Worker quiescence: detaches the timer and stops every callback except the terminal one. */
void enetSessionQuiesce(enet_session_t *session);
bool enetSessionIsAlive(const enet_session_t *session);
bool enetSessionIsConnected(const enet_session_t *session);
/* Local send hold; published before the pressure callback. */
bool enetSessionIsPressured(const enet_session_t *session);
/* Read-only diagnostics for focused tests. */
size_t   enetSessionQueuedBytes(const enet_session_t *session);
uint64_t enetSessionDroppedDatagrams(const enet_session_t *session);
uint64_t enetSessionCloseDeadline(const enet_session_t *session);
