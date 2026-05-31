#include "imported_tunnels.h"
#include "loggers/core_logger.h"
#include "wwapi.h"

#define USING(x) nodelibraryRegister(node##x##Get());

#ifdef INCLUDE_TEMPLATE
#include "tunnels/template/include/interface.h"
#endif

#ifdef INCLUDE_TESTER_CLIENT
#include "tunnels/TesterClient/include/interface.h"
#endif

#ifdef INCLUDE_TESTER_SERVER
#include "tunnels/TesterServer/include/interface.h"
#endif

#ifdef INCLUDE_AUTHENTICATION_SERVER
#include "tunnels/AuthenticationServer/include/interface.h"
#endif

#ifdef INCLUDE_TUN_DEVICE
#include "tunnels/TunDevice/include/interface.h"
#endif

#ifdef INCLUDE_PACKET_SENDER
#include "tunnels/PacketSender/include/interface.h"
#endif

#ifdef INCLUDE_PACKET_RECEIVER
#include "tunnels/PacketReceiver/include/interface.h"
#endif

#ifdef INCLUDE_PACKET_TO_CONNECTION
#include "tunnels/PacketsToConnection/include/interface.h"
#endif

#ifdef INCLUDE__PACKETS_TO_STREAM
#include "tunnels/PacketsToStream/include/interface.h"
#endif

#ifdef INCLUDE_PACKET_SPLIT_STREAM
#include "tunnels/PacketSplitStream/include/interface.h"
#endif

#ifdef INCLUDE_STREAM_TO_PACKETS
#include "tunnels/StreamToPackets/include/interface.h"
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

#ifdef INCLUDE_PING_CLIENT
#include "tunnels/PingClient/include/interface.h"
#endif

#ifdef INCLUDE_PING_SERVER
#include "tunnels/PingServer/include/interface.h"
#endif

#ifdef INCLUDE_KEEPALIVE_CLIENT
#include "tunnels/KeepAliveClient/include/interface.h"
#endif

#ifdef INCLUDE_KEEPALIVE_SERVER
#include "tunnels/KeepAliveServer/include/interface.h"
#endif

#ifdef INCLUDE_CONNECTION_FISHER_CLIENT
#include "tunnels/ConnectionFisherClient/include/interface.h"
#endif

#ifdef INCLUDE_CONNECTION_FISHER_SERVER
#include "tunnels/ConnectionFisherServer/include/interface.h"
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

#ifdef INCLUDE_TLS_CLIENT
#include "tunnels/TlsClient/include/interface.h"
#endif

#ifdef INCLUDE_TLS_SERVER
#include "tunnels/TlsServer/include/interface.h"
#endif

#ifdef INCLUDE_LOGGER_TUNNEL
#include "tunnels/logger/include/interface.h"
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

#ifdef INCLUDE_UDP_OVER_TCP_CLIENT
#include "tunnels/UdpOverTcpClient/include/interface.h"
#endif

#ifdef INCLUDE_UDP_OVER_TCP_SERVER
#include "tunnels/UdpOverTcpServer/include/interface.h"
#endif

#ifdef INCLUDE_TCP_OVER_UDP_CLIENT
#include "tunnels/TcpOverUdpClient/include/interface.h"
#endif

#ifdef INCLUDE_TCP_OVER_UDP_SERVER
#include "tunnels/TcpOverUdpServer/include/interface.h"
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

#ifdef INCLUDE_SNIFF_ROUTER
#include "tunnels/SniffRouter/include/interface.h"
#endif

#ifdef INCLUDE_WOLFSSL_SERVER
#include "tunnels/server/wolfssl/wolfssl_server.h"
#endif

#ifdef INCLUDE_WOLFSSL_CLIENT
#include "tunnels/client/wolfssl/wolfssl_client.h"
#endif

#ifdef INCLUDE_HTTP_SERVER
#include "tunnels/HttpServer/include/interface.h"
#endif

#ifdef INCLUDE_HTTP_CLIENT
#include "tunnels/HttpClient/include/interface.h"
#endif

#ifdef INCLUDE_SOCKS5_CLIENT
#include "tunnels/Socks5Client/include/interface.h"
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

#ifdef INCLUDE_OBFUSCATOR_CLIENT
#include "tunnels/ObfuscatorClient/include/interface.h"
#endif

#ifdef INCLUDE_OBFUSCATOR_SERVER
#include "tunnels/ObfuscatorServer/include/interface.h"
#endif

#ifdef INCLUDE_ENCRYPTION_CLIENT
#include "tunnels/EncryptionClient/include/interface.h"
#endif

#ifdef INCLUDE_ENCRYPTION_SERVER
#include "tunnels/EncryptionServer/include/interface.h"
#endif

#ifdef INCLUDE_PRECONNECT_SERVER
#include "tunnels/server/preconnect/preconnect_server.h"
#endif

#ifdef INCLUDE_PRECONNECT_CLIENT
#include "tunnels/client/preconnect/preconnect_client.h"
#endif

#ifdef INCLUDE_SOCKS_5_SERVER
#include "tunnels/Socks5Server/include/interface.h"
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
#include "tunnels/MuxServer/include/interface.h"
#endif

#ifdef INCLUDE_MUX_CLIENT
#include "tunnels/MuxClient/include/interface.h"
#endif

#ifdef INCLUDE_DISTURBER
#include "tunnels/Disturber/include/interface.h"
#endif

#ifdef INCLUDE_BLACKHOLE
#include "tunnels/BlackHole/include/interface.h"
#endif

#ifdef INCLUDE_SPEEDLIMIT
#include "tunnels/SpeedLimit/include/interface.h"
#endif

void loadImportedTunnelsIntoCore(void)
{

#if INCLUDE_TEMPLATE
    USING(Template);
#endif

#ifdef INCLUDE_TESTER_CLIENT
    USING(TesterClient);
#endif

#ifdef INCLUDE_TESTER_SERVER
    USING(TesterServer);
#endif

#ifdef INCLUDE_AUTHENTICATION_SERVER
    USING(AuthenticationServer);
#endif

#ifdef INCLUDE_TUN_DEVICE
    USING(TunDevice);
#endif

#ifdef INCLUDE_PACKET_SENDER
    USING(PacketSender);
#endif

#ifdef INCLUDE_PACKET_RECEIVER
    USING(PacketReceiver);
#endif

#ifdef INCLUDE_PACKET_TO_CONNECTION
    USING(PacketsToConnection);
#endif

#ifdef INCLUDE__PACKETS_TO_STREAM
    USING(PacketsToStream);
#endif

#ifdef INCLUDE_PACKET_SPLIT_STREAM
    USING(PacketSplitStream);
#endif

#ifdef INCLUDE_STREAM_TO_PACKETS
    USING(StreamToPackets);
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

#ifdef INCLUDE_PING_CLIENT
    USING(PingClient);
#endif

#ifdef INCLUDE_PING_SERVER
    USING(PingServer);
#endif

#ifdef INCLUDE_KEEPALIVE_CLIENT
    USING(KeepAliveClient);
#endif

#ifdef INCLUDE_KEEPALIVE_SERVER
    USING(KeepAliveServer);
#endif

#ifdef INCLUDE_CONNECTION_FISHER_CLIENT
    USING(ConnectionFisherClient);
#endif

#ifdef INCLUDE_CONNECTION_FISHER_SERVER
    USING(ConnectionFisherServer);
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

#ifdef INCLUDE_TLS_CLIENT
    USING(TlsClient);
#endif

#ifdef INCLUDE_TLS_SERVER
    USING(TlsServer);
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

#ifdef INCLUDE_UDP_OVER_TCP_CLIENT
    USING(UdpOverTcpClient);
#endif

#ifdef INCLUDE_UDP_OVER_TCP_SERVER
    USING(UdpOverTcpServer);
#endif

#ifdef INCLUDE_TCP_OVER_UDP_CLIENT
    USING(TcpOverUdpClient);
#endif

#ifdef INCLUDE_TCP_OVER_UDP_SERVER
    USING(TcpOverUdpServer);
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

#ifdef INCLUDE_SNIFF_ROUTER
    USING(SniffRouter);
#endif

#ifdef INCLUDE_WOLFSSL_SERVER
    USING(WolfSSLServer);
#endif

#ifdef INCLUDE_WOLFSSL_CLIENT
    USING(WolfSSLClient);
#endif

#ifdef INCLUDE_HTTP_SERVER
    USING(HttpServer);
#endif

#ifdef INCLUDE_HTTP_CLIENT
    USING(HttpClient);
#endif

#ifdef INCLUDE_SOCKS5_CLIENT
    USING(Socks5Client);
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

#ifdef INCLUDE_OBFUSCATOR_CLIENT
    USING(ObfuscatorClient);
#endif

#ifdef INCLUDE_OBFUSCATOR_SERVER
    USING(ObfuscatorServer);
#endif

#ifdef INCLUDE_ENCRYPTION_CLIENT
    USING(EncryptionClient);
#endif

#ifdef INCLUDE_ENCRYPTION_SERVER
    USING(EncryptionServer);
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

#ifdef INCLUDE_DISTURBER
    USING(Disturber);
#endif

#ifdef INCLUDE_BLACKHOLE
    USING(BlackHole);
#endif

#ifdef INCLUDE_SPEEDLIMIT
    USING(SpeedLimit);
#endif
}
