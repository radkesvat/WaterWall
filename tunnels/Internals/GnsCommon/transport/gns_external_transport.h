/*
 * External transport for GameNetworkingSockets.
 *
 * steamnetworkingsockets_externaltransport.cpp is compiled in place of
 * upstream's steamnetworkingsockets_socketthread.cpp.  With it the library
 * never creates or uses an OS socket: every outgoing datagram is handed to a
 * callback, and every incoming datagram is handed to the library with
 * gns_external_receive().
 *
 * Addresses are synthetic.  They never reach an OS call; the library only uses
 * them as lookup keys and prints them in log lines.
 *
 * How the ordinary public API finds an endpoint:
 *   - ISteamNetworkingSockets::CreateListenSocketIP( local ) binds to the
 *     endpoint that was registered with gns_external_endpoint_create_listen( local ).
 *   - ISteamNetworkingSockets::ConnectByIPAddress( remote ) binds to the
 *     endpoint that was registered with gns_external_endpoint_create_connect( remote ).
 *     One endpoint carries one outgoing connection, so every outgoing
 *     connection needs its own synthetic remote address.
 *
 * Threading rules:
 *   - Both callbacks are invoked with library locks held (the global lock and
 *     usually a connection lock), from the library's service thread, from
 *     inside gns_external_receive(), or from inside a public API call.  They
 *     must only record what they are given and return.  They must not call
 *     back into the library and must not take a lock that is ever held around
 *     a library call.
 *   - gns_external_receive() takes the library's global lock, may block for a
 *     short time, and may invoke the callbacks of any endpoint before it
 *     returns.
 *   - After gns_external_endpoint_release() returns, the callbacks of that
 *     endpoint are never invoked again and the handle must not be used.
 */
#ifndef GNS_EXTERNAL_TRANSPORT_H
#define GNS_EXTERNAL_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Largest datagram the library sends or accepts (k_cbSteamNetworkingSocketsMaxUDPMsgLen). */
#define GNS_EXTERNAL_MAX_DATAGRAM 1300

typedef struct gns_external_endpoint gns_external_endpoint_t;

/* Synthetic address.  ip is an IPv6 address in network byte order; an IPv4
 * address a.b.c.d is written as ::ffff:a.b.c.d.  port is in host byte order. */
typedef struct gns_external_addr
{
	uint8_t ip[16];
	uint16_t port;
} gns_external_addr_t;

typedef enum gns_external_event
{
	/* Listen endpoint: the last remote host that was bound to it has been
	 * closed.  The listen socket itself is still open. */
	GNS_EXTERNAL_EVENT_IDLE = 1,
	/* The library closed the listen socket or the connection that was bound to
	 * the endpoint.  The endpoint stays registered and can be bound again. */
	GNS_EXTERNAL_EVENT_CLOSED = 2,
} gns_external_event_t;

/* Outgoing datagram.  `data` is only valid during the call.  `to` is the
 * synthetic destination: for a listen endpoint it is the `from` address that
 * was passed to gns_external_receive() for that peer; for a connect endpoint
 * it is always the registered remote address. */
typedef void ( *gns_external_send_fn )( void *user, const uint8_t *data, size_t length, const gns_external_addr_t *to );

/* What the library did with the endpoint. */
typedef void ( *gns_external_event_fn )( void *user, gns_external_event_t event );

/* Register an endpoint for a listen socket.  `local` must have a nonzero port.
 * `event` may be NULL.  Returns NULL if the address is already registered. */
gns_external_endpoint_t *gns_external_endpoint_create_listen( const gns_external_addr_t *local, gns_external_send_fn send, gns_external_event_fn event, void *user );

/* Register an endpoint for one outgoing connection to `remote`.  `event` may
 * be NULL.  Returns NULL if the address is already registered. */
gns_external_endpoint_t *gns_external_endpoint_create_connect( const gns_external_addr_t *remote, gns_external_send_fn send, gns_external_event_fn event, void *user );

/* Hand one received datagram to the library.  `from` is the synthetic source
 * address; for a connect endpoint it may be NULL (the registered remote
 * address is used).  Returns false if the datagram was dropped because no
 * listen socket or connection is currently bound to the endpoint, the library
 * is not initialised, or length is larger than GNS_EXTERNAL_MAX_DATAGRAM. */
bool gns_external_receive( gns_external_endpoint_t *endpoint, const gns_external_addr_t *from, const uint8_t *data, size_t length );

/* Remove the registration.  If a listen socket or connection is still bound
 * to the endpoint, its outgoing datagrams are discarded from now on and the
 * object is freed when the library closes it. */
void gns_external_endpoint_release( gns_external_endpoint_t *endpoint );

#ifdef __cplusplus
}
#endif

#endif /* GNS_EXTERNAL_TRANSPORT_H */
