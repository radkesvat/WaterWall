#include "imported_tunnels.h"
#include "loggers/core_logger.h"
#include "wwapi.h"

#define USING(x) nodelibraryRegister(node##x##Get());


#ifdef INCLUDE_TEMPLATE
#include "tunnels/template/include/interface.h"
#endif

#ifdef INCLUDE_TUN_DEVICE
#include "tunnels/TunDevice/include/interface.h"
#endif

#ifdef INCLUDE_PACKET_TO_CONNECTION
#include "tunnels/PacketToConnection/include/interface.h"
#endif

#ifdef INCLUDE_PACKET_AS_DATA
#include "tunnels/PacketAsData/include/interface.h"
#endif

#ifdef INCLUDE_DATA_AS_PACKET
#include "tunnels/DataAsPacket/include/interface.h"
#endif

#ifdef INCLUDE_WIREGUARD_DEVICE
#include "tunnels/WireGuardDevice/include/interface.h"
#endif


#ifdef INCLUDE_LAYER3_IP_ROUTING_TABLE
#include "tunnels/layer3/ip/routing_table/ip_routing_table.h"
#endif

#ifdef INCLUDE_IP_OVERRIDER
#include "tunnels/IpOverrider/include/interface.h"
#endif

#ifdef INCLUDE_IP_MANIPULATOR
#include "tunnels/IpManipulator/include/interface.h"
#endif

#ifdef INCLUDE_LAYER3_TCP_MANIPULATOR
#include "tunnels/layer3/tcp/manipulator/tcp_manipulator.h"
#endif

#ifdef INCLUDE_TCP_LISTENER
#include "tunnels/TcpListener/include/interface.h"
#endif

#ifdef INCLUDE_UDP_LISTENER
#include "tunnels/UdpListener/include/interface.h"
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
#include "tunnels/TcpConnector/include/interface.h"
#endif

#ifdef INCLUDE_UDP_CONNECTOR
#include "tunnels/UdpConnector/include/interface.h"
#endif

#ifdef INCLUDE_UDP_STATELESS_SOCKET
#include "tunnels/UdpStatelessSocket/include/interface.h"
#endif

#ifdef INCLUDE_RAWSOCKET
#include "tunnels/RawSocket/include/interface.h"
#endif

#ifdef INCLUDE_BRIDGE
#include "tunnels/Bridge/include/interface.h"
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
#include "tunnels/ReverseServer/include/interface.h"
#endif

#ifdef INCLUDE_REVERSE_CLIENT
#include "tunnels/ReverseClient/include/interface.h"
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
#include "tunnels/HalfDuplexServer/include/interface.h"
#endif

#ifdef INCLUDE_HALFDUPLEX_CLIENT
#include "tunnels/HalfDuplexClient/include/interface.h"
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
#include "tunnels/MuxClient/include/interface.h"
#endif

void loadImportedTunnelsIntoCore(void)
{

#if INCLUDE_TEMPLATE
    USING(Template);
#endif

#ifdef INCLUDE_TUN_DEVICE
    USING(TunDevice);
#endif

#ifdef INCLUDE_PACKET_TO_CONNECTION
    USING(PacketToConnection);
#endif

#ifdef INCLUDE_PACKET_AS_DATA
    USING(PacketAsData);
#endif

#ifdef INCLUDE_DATA_AS_PACKET
    USING(DataAsPacket);
#endif

#ifdef INCLUDE_WIREGUARD_DEVICE
    USING(WireGuardDevice);
#endif


#ifdef INCLUDE_LAYER3_IP_ROUTING_TABLE
    USING(Layer3IpRoutingTable);
#endif

#ifdef INCLUDE_IP_OVERRIDER
    USING(IpOverrider);
#endif

#ifdef INCLUDE_IP_MANIPULATOR
    USING(IpManipulator);
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

#ifdef INCLUDE_UDP_STATELESS_SOCKET
    USING(UdpStatelessSocket);
#endif

#ifdef INCLUDE_RAWSOCKET
    USING(RawSocket);
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
    USING(MuxServer);
#endif

#ifdef INCLUDE_MUX_CLIENT
    USING(MuxClient);
#endif
}
