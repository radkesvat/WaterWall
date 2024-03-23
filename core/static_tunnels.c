#include "ww.h"
#include "library_loader.h"
#include "loggers/core_logger.h"


#define USING(x)                                                                       \
    do                                                                                 \
    {                                                                                  \
        hash_t h = calcHashLen(#x, strlen(#x));                                        \
        registerStaticLib((tunnel_lib_t){h,                                            \
                                         new##x, api##x, destroy##x, getMetadata##x}); \
        LOGD("Imported static tunnel lib%s.a  hash:%lx", #x, h);                       \
    } while (0)


#ifdef INCLUDE_TCP_LISTENER
#include "tunnels/adapters/tcp_listener/tcp_listener.h"
#endif

#ifdef INCLUDE_OPENSSL_SERVER
#include "tunnels/server/openssl/openssl_server.h"
#endif

#ifdef INCLUDE_OPENSSL_CLIENT
#include "tunnels/client/openssl/openssl_client.h"
#endif

#ifdef INCLUDE_LOGGER_TUNNEL
#include "tunnels/logger/logger_tunnel.h"
#endif

#ifdef INCLUDE_TROJAN_AUTH_SERVER
#include "tunnels/server/trojan/auth/trojan_auth_server.h"
#endif

#ifdef INCLUDE_TROJAN_SOCKS_SERVER
#include "tunnels/server/trojan/socks/trojan_socks_server.h"
#endif

#ifdef INCLUDE_CONNECTOR
#include "tunnels/adapters/connector/connector.h"
#endif

#ifdef INCLUDE_TCPCONNECTOR
#include "tunnels/adapters/tcp_connector/tcp_connector.h"
#endif

#ifdef INCLUDE_WOLFSSL_SERVER
#include "tunnels/server/wolfssl/wolfssl_server.h"
#endif

#ifdef INCLUDE_HTTP2_SERVER
#include "tunnels/server/http2/http2_server.h"
#endif

#ifdef INCLUDE_HTTP2_CLIENT
#include "tunnels/client/http2/http2_client.h"
#endif

#ifdef INCLUDE_PROTOBUF_SERVER
#include "tunnels/server/protobuf/protobuf_server.h"
#endif

#ifdef INCLUDE_PROTOBUF_CLIENT
#include "tunnels/client/protobuf/protobuf_client.h"
#endif




void loadStaticTunnelsIntoCore()
{
#ifdef INCLUDE_TCP_LISTENER
    USING(TcpListener);
#endif

#ifdef INCLUDE_OPENSSL_SERVER
    USING(OpenSSLServer);
#endif

#ifdef INCLUDE_OPENSSL_CLIENT
    USING(OpenSSLClient);
#endif

#ifdef INCLUDE_LOGGER_TUNNEL
    USING(LoggerTunnel);
#endif

#ifdef INCLUDE_TROJAN_AUTH_SERVER
    USING(TrojanAuthServer);
#endif

#ifdef INCLUDE_TROJAN_SOCKS_SERVER
    USING(TrojanSocksServer);
#endif

#ifdef INCLUDE_CONNECTOR
    USING(Connector);
#endif

#ifdef INCLUDE_TCPCONNECTOR
    USING(TcpConnector);
#endif

#ifdef INCLUDE_WOLFSSL_SERVER
    USING(WolfSSLServer);
#endif

#ifdef INCLUDE_HTTP2_SERVER
    USING(Http2Server);
#endif

#ifdef INCLUDE_HTTP2_CLIENT
    USING(Http2Client);
#endif

#ifdef INCLUDE_PROTOBUF_SERVER
    USING(ProtoBufServer);
#endif

// #ifdef INCLUDE_PROTOBUF_CLIENT
// #include "tunnels/client/protobuf/protobuf_client.h"
// #endif





}