#include "ww.h"
#include "library_loader.h"
#include "loggers/core_logger.h"

#ifdef INCLUDE_TCP_LISTENER
#include "tunnels/adapters/tcp_listener/tcp_listener.h"
#endif

#ifdef INCLUDE_OPENSSL_SERVER
#include "tunnels/server/openssl/openssl_server.h"
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


#define USING(x)                                                       \
    do                                                                 \
    {                                                                  \
        hash_t h = calcHashLen(#x, strlen(#x));                        \
        registerStaticLib((tunnel_lib_t){h,                            \
            new##x, api##x, destroy##x,getMetadata##x}); \
        LOGD("Imported static tunnel lib%s.a  hash:%lx", #x, h);       \
    } while (0)

void loadStaticTunnelsIntoCore()
{
#ifdef INCLUDE_TCP_LISTENER
    USING(TcpListener);
#endif

#ifdef INCLUDE_OPENSSL_SERVER
    USING(OpenSSLServer);
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


}