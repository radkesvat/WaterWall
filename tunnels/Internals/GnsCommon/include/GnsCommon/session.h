#pragma once

#include "wwapi.h"

#include "GnsCommon/settings.h"

/*
 * One GNS session on one WaterWall worker.
 *
 * A session owns one external endpoint, the port behind it and one GNS connection. A client connects through its
 * endpoint. A server opens its own listen socket on its endpoint and accepts the one native connection of its
 * carrier, as an ENet server session owns one host. GameNetworkingSockets runs its own service thread; what that
 * thread sends reaches the session through the port, and the session hands datagrams and stream bytes to the node
 * only from its worker, after the library call has returned, so a neighbouring tunnel can never reenter GNS.
 *
 * Calls made from inside a callback are queued and run in order by the call that is already driving the session.
 * Every call for one session happens on its worker. The process-wide runtime (gnsRuntimeAcquire) must be held
 * while a session exists.
 */

typedef struct gns_session_s gns_session_t;

typedef enum gns_session_result_e
{
    kGnsSessionClosed,          /* the local close finished */
    kGnsSessionPeerClosed,      /* the peer closed, or it stopped answering */
    kGnsSessionAborted,         /* the owner aborted: the carrier finished or the worker is stopping */
    kGnsSessionDrainTimeout,    /* close-drain-timeout-ms expired before the peer acknowledged everything */
    kGnsSessionConnectTimeout,  /* the native handshake did not finish in time */
    kGnsSessionProtocolFailure, /* GNS failed, or the path is beyond what its packet numbering can carry */
    kGnsSessionCapacityFailure, /* the hard send cap or the nested-input budget refused data */
} gns_session_result_t;

typedef struct gns_session_config_s
{
    gns_settings_t settings;
    bool           client; /* true connects; false waits for the one connection of its carrier */
    wid_t          wid;    /* the worker that owns the session */
    buffer_pool_t *pool;   /* that worker's pool; outlives the session */
    wloop_t       *loop;   /* that worker's loop */
} gns_session_config_t;

typedef struct gns_session_callbacks_s
{
    /* emit and payload transfer the entire buffer on every return. */
    void (*emit)(void *user, sbuf_t *packet);
    void (*payload)(void *user, sbuf_t *payload);
    /* The native handshake finished. Called once, before the first payload. */
    void (*connected)(void *user);
    /* The local send hold changed. The new state is published before the call. */
    void (*pressure)(void *user, bool paused);
    /* The session ended. Called once. It may release the owner's reference; destroy_user runs at final release. */
    void (*terminal)(void *user, gns_session_result_t result);
    void (*destroy_user)(void *user);
} gns_session_callbacks_t;

/* Create owns one reference. Returns NULL when the endpoint or the worker timer cannot be created. */
gns_session_t *gnsSessionCreate(const gns_session_config_t *config, const gns_session_callbacks_t *callbacks,
                                void *user);
void           gnsSessionRetain(gns_session_t *session);
void           gnsSessionRelease(gns_session_t *session);
/* Start after the neighbouring Init has safely returned. Nothing is emitted before it. */
void gnsSessionStart(gns_session_t *session);
/* Send takes ownership of application bytes. They are dropped after AppFinish, and by a server that has no
 * connection yet: its application starts with the connected callback. */
void gnsSessionSend(gns_session_t *session, sbuf_t *payload);
/* Input takes ownership of one carrier datagram. */
void gnsSessionInput(gns_session_t *session, sbuf_t *packet);
/* The application finished: deliver what was accepted, then close. Ends with kGnsSessionClosed, or with
 * kGnsSessionDrainTimeout at the deadline. */
void gnsSessionAppFinish(gns_session_t *session);
/* Ends the session now and runs the terminal callback before returning. Nothing is emitted. */
void gnsSessionAbort(gns_session_t *session, gns_session_result_t result);
/* Worker quiescence: detaches the timer and stops every callback except the terminal one. */
void gnsSessionQuiesce(gns_session_t *session);
bool gnsSessionIsAlive(const gns_session_t *session);
bool gnsSessionIsConnected(const gns_session_t *session);
/* Local send hold; published before the pressure callback. */
bool gnsSessionIsPressured(const gns_session_t *session);
/* Read-only diagnostics for focused tests. */
uint64_t gnsSessionOutstandingBytes(const gns_session_t *session);
size_t   gnsSessionOutstandingMessages(const gns_session_t *session);
uint64_t gnsSessionRefusedDatagrams(const gns_session_t *session);
uint64_t gnsSessionCloseDeadline(const gns_session_t *session);
