#include "imported_tunnels.h"
#include "library_loader.h"
#include "loggers/core_logger.h"
#include "worker.h"

#define USING(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        hash_t h = calcHashBytes(#x, strlen(#x));                                                                    \
        nodelibraryRegister((node_lib_t) {                                                                             \
            .hash_name         = h,                                                                                    \
            .createHandle      = new##x,                                                                               \
            .destroyHandle     = destroy##x,                                                                           \
            .apiHandle         = api##x,                                                                               \
            .getMetadataHandle = getMetadata##x,                                                                       \
        });                                                                                                            \
        LOGD("Imported static tunnel lib%-20s  hash:%lx", #x, h);                                                      \
    } while (0);

#ifdef INCLUDE_TUNDEVICE
#include "tunnels/adapters/device/tun/tun_device.h"
#endif

#ifdef INCLUDE_RAWDEVICE
#include "tunnels/adapters/device/raw/raw_device.h"
#endif

#ifdef INCLUDE_CAPTUREDEVICE
#include "tunnels/adapters/device/capture/caputre_device.h"
#endif

#ifdef INCLUDE_LAYER3_RECEIVER
#include "tunnels/layer3/receiver/receiver.h"
#endif

#ifdef INCLUDE_LAYER3_SENDER
#include "tunnels/layer3/sender/sender.h"
#endif

#ifdef INCLUDE_LAYER3_IP_ROUTING_TABLE
#include "tunnels/layer3/ip/routing_table/ip_routing_table.h"
#endif

#ifdef INCLUDE_LAYER3_IP_OVERRIDER
#include "tunnels/layer3/ip/overrider/ip_overrider.h"
#endif

#ifdef INCLUDE_LAYER3_IP_MANIPULATOR
#include "tunnels/layer3/ip/manipulator/ip_manipulator.h"
#endif


#ifdef INCLUDE_LAYER3_TCP_MANIPULATOR
#include "tunnels/layer3/tcp/manipulator/tcp_manipulator.h"
#endif

#ifdef INCLUDE_TCP_LISTENER
#include "tunnels/adapters/listener/tcp/tcp_listener.h"
#endif

#ifdef INCLUDE_UDP_LISTENER
#include "tunnels/adapters/listener/udp/udp_listener.h"
#endif

#ifdef INCLUDE_LISTENER
#include "tunnels/adapters/listener/listener.h"
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
#include "tunnels/adapters/connector/tcp/tcp_connector.h"
#endif

#ifdef INCLUDE_UDP_CONNECTOR
#include "tunnels/adapters/connector/udp/udp_connector.h"
#endif

#ifdef INCLUDE_BRIDGE
#include "tunnels/adapters/bridge/bridge.h"
#endif

#ifdef INCLUDE_WOLFSSL_SERVER
#include "tunnels/server/wolfssl/wolfssl_server.h"
#endif

#ifdef INCLUDE_WOLFSSL_CLIENT
#include "tunnels/client/wolfssl/wolfssl_client.h"
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

#ifdef INCLUDE_REVERSE_SERVER
#include "tunnels/server/reverse/reverse_server.h"
#endif

#ifdef INCLUDE_REVERSE_CLIENT
#include "tunnels/client/reverse/reverse_client.h"
#endif

#ifdef INCLUDE_HEADER_SERVER
#include "tunnels/server/header/header_server.h"
#endif

#ifdef INCLUDE_HEADER_CLIENT
#include "tunnels/client/header/header_client.h"
#endif

#ifdef INCLUDE_PRECONNECT_SERVER
#include "tunnels/server/preconnect/preconnect_server.h"
#endif

#ifdef INCLUDE_PRECONNECT_CLIENT
#include "tunnels/client/preconnect/preconnect_client.h"
#endif

#ifdef INCLUDE_SOCKS_5_SERVER
#include "tunnels/server/socks/5/socks5_server.h"
#endif

#ifdef INCLUDE_REALITY_SERVER
#include "tunnels/server/reality/reality_server.h"
#endif

#ifdef INCLUDE_REALITY_CLIENT
#include "tunnels/client/reality/reality_client.h"
#endif

#ifdef INCLUDE_HALFDUPLEX_SERVER
#include "tunnels/server/halfduplex/halfduplex_server.h"
#endif

#ifdef INCLUDE_HALFDUPLEX_CLIENT
#include "tunnels/client/halfduplex/halfduplex_client.h"
#endif

#ifdef INCLUDE_BGP4_SERVER
#include "tunnels/server/bgp4/bgp4_server.h"
#endif

#ifdef INCLUDE_BGP4_CLIENT
#include "tunnels/client/bgp4/bgp4_client.h"
#endif

#ifdef INCLUDE_MUX_SERVER
#include "tunnels/server/mux/mux_server.h"
#endif

#ifdef INCLUDE_MUX_CLIENT
#include "tunnels/client/mux/mux_client.h"
#endif

void loadImportedTunnelsIntoCore(void)
{

#ifdef INCLUDE_TUNDEVICE
    USING(TunDevice);
#endif

#ifdef INCLUDE_RAWDEVICE
    USING(RawDevice);
#endif

#ifdef INCLUDE_CAPTUREDEVICE
    USING(CaptureDevice);
#endif

#ifdef INCLUDE_LAYER3_RECEIVER
    USING(Layer3Receiver);
#endif

#ifdef INCLUDE_LAYER3_SENDER
    USING(Layer3Sender);
#endif

#ifdef INCLUDE_LAYER3_IP_ROUTING_TABLE
    USING(Layer3IpRoutingTable);
#endif

#ifdef INCLUDE_LAYER3_IP_OVERRIDER
    USING(Layer3IpOverrider);
#endif

#ifdef INCLUDE_LAYER3_IP_MANIPULATOR
    USING(Layer3IpManipulator);
#endif

#ifdef INCLUDE_LAYER3_TCP_MANIPULATOR
    USING(Layer3TcpManipulator);
#endif

#ifdef INCLUDE_TCP_LISTENER
    USING(TcpListener);
#endif

#ifdef INCLUDE_UDP_LISTENER
    USING(UdpListener);
#endif

#ifdef INCLUDE_LISTENER
    USING(Listener);
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

#ifdef INCLUDE_UDP_CONNECTOR
    USING(UdpConnector);
#endif

#ifdef INCLUDE_BRIDGE
    USING(Bridge);
#endif

#ifdef INCLUDE_WOLFSSL_SERVER
    USING(WolfSSLServer);
#endif

#ifdef INCLUDE_WOLFSSL_CLIENT
    USING(WolfSSLClient);
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

#ifdef INCLUDE_PROTOBUF_CLIENT
    USING(ProtoBufClient);
#endif

#ifdef INCLUDE_REVERSE_SERVER
    USING(ReverseServer);
#endif

#ifdef INCLUDE_REVERSE_CLIENT
    USING(ReverseClient);
#endif

#ifdef INCLUDE_HEADER_SERVER
    USING(HeaderServer);
#endif

#ifdef INCLUDE_HEADER_CLIENT
    USING(HeaderClient);
#endif

#ifdef INCLUDE_PRECONNECT_SERVER
    USING(PreConnectServer);
#endif

#ifdef INCLUDE_PRECONNECT_CLIENT
    USING(PreConnectClient);
#endif

#ifdef INCLUDE_SOCKS_5_SERVER
    USING(Socks5Server);
#endif

#ifdef INCLUDE_REALITY_SERVER
    USING(RealityServer);
#endif

#ifdef INCLUDE_REALITY_CLIENT
    USING(RealityClient);
#endif

#ifdef INCLUDE_HALFDUPLEX_CLIENT
    USING(HalfDuplexClient);
#endif

#ifdef INCLUDE_HALFDUPLEX_SERVER
    USING(HalfDuplexServer);
#endif

#ifdef INCLUDE_BGP4_SERVER
    USING(Bgp4Server);
#endif

#ifdef INCLUDE_BGP4_CLIENT
    USING(Bgp4Client);
#endif

#ifdef INCLUDE_MUX_SERVER
    USING(MuxClient);
#endif

#ifdef INCLUDE_MUX_CLIENT
    USING(MuxServer);
#endif
}
