#pragma once

#include "gns_external_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The one door to GameNetworkingSockets' C++ interface. Every function is a thin call into the library; the session
 * logic stays in C.
 *
 * The library exists once per process. gnsEngineAcquire() starts it for its first user and gnsEngineRelease() stops
 * it after the last one. Every setting travels with a listen socket or a connection, never as a global value, so
 * users with different settings share the library.
 *
 * Listen sockets and connections are opened on external endpoints (gns_external_transport.h): register the endpoint
 * under a synthetic address first, then pass the same address here. Handles are the library's own; zero is never a
 * valid one.
 */

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct gns_engine_options_s
    {
        int32_t packet_size;          /* MTU_PacketSize */
        int32_t send_rate;            /* SendRateMin and SendRateMax, bytes per second */
        int32_t timeout_initial_ms;   /* TimeoutInitial */
        int32_t timeout_connected_ms; /* TimeoutConnected */
        int32_t receive_buffer;       /* RecvBufferSize */
        int32_t receive_messages;     /* RecvBufferMessages */
        int32_t receive_message_max;  /* RecvMaxMessageSize */
    } gns_engine_options_t;

    typedef enum gns_engine_state_e
    {
        kGnsEngineGone,       /* the handle is not a connection any more */
        kGnsEngineConnecting, /* the handshake is in progress */
        kGnsEngineConnected,
        kGnsEngineClosedByPeer, /* the peer closed; everything it sent before that can still be received */
        kGnsEngineFailed,       /* the library gave the connection up: a timeout or a protocol problem */
    } gns_engine_state_t;

    typedef struct gns_engine_status_s
    {
        gns_engine_state_t state;
        uint32_t           queued_bytes;       /* reliable bytes that have not been sent */
        uint32_t           unacked_bytes;      /* reliable bytes that were sent and are not acknowledged */
        uint32_t           ping_ms;            /* the library's round-trip estimate */
        uint32_t           packets_per_second; /* outgoing packets, as the library measures them */
    } gns_engine_status_t;

    typedef enum gns_engine_send_e
    {
        kGnsEngineSendAccepted,
        kGnsEngineSendRefused, /* the library's own send buffer is full */
        kGnsEngineSendFailed,  /* there is no connection to send on */
    } gns_engine_send_t;

    typedef struct gns_engine_message_s
    {
        const uint8_t *data;
        uint32_t       size;
        void          *handle; /* the library's message; released with gnsEngineMessagesRelease() */
    } gns_engine_message_t;

    typedef enum gns_engine_log_e
    {
        kGnsEngineLogError,   /* a failed assertion or an error inside the library */
        kGnsEngineLogWarning, /* something the library calls important */
        kGnsEngineLogDebug,   /* its warnings, which include lock timing under load */
    } gns_engine_log_t;

    /* The library's own messages. Called on any thread, with library locks held: log and return. */
    typedef void (*gns_engine_log_fn)(gns_engine_log_t level, const char *text);

    /* A listen socket has an incoming connection. token is the value that was given to gnsEngineListen(). Called on
     * whichever thread runs gnsEngineRunAccepts(), with no library lock held. Return true to accept the connection. */
    typedef bool (*gns_engine_admit_fn)(int64_t token, uint32_t connection);

    /* The first successful call starts the library and installs both callbacks; later calls only count. Returns false
     * and writes the library's reason into error when it cannot start. */
    bool gnsEngineAcquire(gns_engine_log_fn log, gns_engine_admit_fn admit, char *error, size_t error_capacity);
    /* The last call stops the library. Every listen socket and connection must be closed by then. */
    void gnsEngineRelease(void);

    /* Opens a listen socket on the endpoint registered under local. Returns 0 on failure. */
    uint32_t gnsEngineListen(const gns_external_addr_t *local, const gns_engine_options_t *options, int64_t token);
    /* Closes the listen socket and, ungracefully, every connection that still belongs to it. */
    void gnsEngineCloseListen(uint32_t listen_socket);
    /* Starts a connection through the endpoint registered under remote. Returns 0 on failure. */
    uint32_t gnsEngineConnect(const gns_external_addr_t *remote, const gns_engine_options_t *options);
    /* Offers waiting incoming connections to the admit callback. Cheap when nothing waits. */
    void gnsEngineRunAccepts(void);

    void              gnsEngineStatus(uint32_t connection, gns_engine_status_t *status);
    gns_engine_send_t gnsEngineSend(uint32_t connection, const uint8_t *data, uint32_t length);
    /* Takes up to capacity received messages, oldest first. Returns their number. */
    int  gnsEngineReceive(uint32_t connection, gns_engine_message_t *messages, int capacity);
    void gnsEngineMessagesRelease(gns_engine_message_t *messages, int count);
    /* Ends the connection now. The library tells the peer once and answers its packets for a few seconds more. */
    void gnsEngineClose(uint32_t connection);
    /* The library's reason for the end of a connection, for a log line. Returns its numeric code, 0 when there is none.
     */
    int gnsEngineEndReason(uint32_t connection, char *text, size_t capacity);

#ifdef __cplusplus
}
#endif
