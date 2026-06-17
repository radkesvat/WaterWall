#include "imported_tunnels.h"
#include "loggers/core_logger.h"
#include "wwapi.h"

#define USING(x) nodelibraryRegister(node##x##Get());

#ifdef INCLUDE_TEMPLATE
#include "Template/interface.h"
#endif

#ifdef INCLUDE_TESTER_CLIENT
#include "TesterClient/interface.h"
#endif

#ifdef INCLUDE_TESTER_SERVER
#include "TesterServer/interface.h"
#endif

#ifdef INCLUDE_SPEEDTEST_CLIENT
#include "SpeedTestClient/interface.h"
#endif

#ifdef INCLUDE_SPEEDTEST_SERVER
#include "SpeedTestServer/interface.h"
#endif

#ifdef INCLUDE_AUTHENTICATION_CLIENT
#include "AuthenticationClient/interface.h"
#endif

#ifdef INCLUDE_AUTHENTICATION_SERVER
#include "AuthenticationServer/interface.h"
#endif

#ifdef INCLUDE_TUN_DEVICE
#include "TunDevice/interface.h"
#endif

#ifdef INCLUDE_PACKET_SENDER
#include "PacketSender/interface.h"
#endif

#ifdef INCLUDE_PACKET_RECEIVER
#include "PacketReceiver/interface.h"
#endif

#ifdef INCLUDE_PACKET_TO_CONNECTION
#include "PacketsToConnection/interface.h"
#endif

#ifdef INCLUDE_PACKETS_TO_STREAM
#include "PacketsToStream/interface.h"
#endif

#ifdef INCLUDE_PACKET_SPLIT_STREAM
#include "PacketSplitStream/interface.h"
#endif

#ifdef INCLUDE_STREAM_TO_PACKETS
#include "StreamToPackets/interface.h"
#endif

#ifdef INCLUDE_WIREGUARD_DEVICE
#include "WireGuardDevice/interface.h"
#endif

#ifdef INCLUDE_LAYER3_IP_ROUTING_TABLE
#include "tunnels/layer3/ip/routing_table/ip_routing_table.h"
#endif

#ifdef INCLUDE_IP_OVERRIDER
#include "IpOverrider/interface.h"
#endif

#ifdef INCLUDE_IP_MANIPULATOR
#include "IpManipulator/interface.h"
#endif

#ifdef INCLUDE_PING_CLIENT
#include "PingClient/interface.h"
#endif

#ifdef INCLUDE_PING_SERVER
#include "PingServer/interface.h"
#endif

#ifdef INCLUDE_KEEPALIVE_CLIENT
#include "KeepAliveClient/interface.h"
#endif

#ifdef INCLUDE_KEEPALIVE_SERVER
#include "KeepAliveServer/interface.h"
#endif

#ifdef INCLUDE_CONNECTION_FISHER_CLIENT
#include "ConnectionFisherClient/interface.h"
#endif

#ifdef INCLUDE_CONNECTION_FISHER_SERVER
#include "ConnectionFisherServer/interface.h"
#endif

#ifdef INCLUDE_LAYER3_TCP_MANIPULATOR
#include "tunnels/layer3/tcp/manipulator/tcp_manipulator.h"
#endif

#ifdef INCLUDE_TCP_LISTENER
#include "TcpListener/interface.h"
#endif

#ifdef INCLUDE_UDP_LISTENER
#include "UdpListener/interface.h"
#endif

#ifdef INCLUDE_TCP_UDP_LISTENER
#include "TcpUdpListener/interface.h"
#endif

#ifdef INCLUDE_OPENSSL_SERVER
#include "tunnels/server/openssl/openssl_server.h"
#endif

#ifdef INCLUDE_TLS_CLIENT
#include "TlsClient/interface.h"
#endif

#ifdef INCLUDE_TLS_SERVER
#include "TlsServer/interface.h"
#endif

#ifdef INCLUDE_TROJAN_CLIENT
#include "TrojanClient/interface.h"
#endif

#ifdef INCLUDE_TROJAN_SERVER
#include "TrojanServer/interface.h"
#endif

#ifdef INCLUDE_VLESS_SERVER
#include "VlessServer/interface.h"
#endif

#ifdef INCLUDE_LOGGER_TUNNEL
#include "LoggerTunnel/interface.h"
#endif

#ifdef INCLUDE_TROJAN_AUTH_SERVER
#include "tunnels/server/trojan/auth/trojan_auth_server.h"
#endif

#ifdef INCLUDE_TROJAN_SOCKS_SERVER
#include "tunnels/server/trojan/socks/trojan_socks_server.h"
#endif

#ifdef INCLUDE_TCPCONNECTOR
#include "TcpConnector/interface.h"
#endif

#ifdef INCLUDE_UDP_CONNECTOR
#include "UdpConnector/interface.h"
#endif

#ifdef INCLUDE_TCP_UDP_CONNECTOR
#include "TcpUdpConnector/interface.h"
#endif

#ifdef INCLUDE_UDP_OVER_TCP_CLIENT
#include "UdpOverTcpClient/interface.h"
#endif

#ifdef INCLUDE_UDP_OVER_TCP_SERVER
#include "UdpOverTcpServer/interface.h"
#endif

#ifdef INCLUDE_TCP_OVER_UDP_CLIENT
#include "TcpOverUdpClient/interface.h"
#endif

#ifdef INCLUDE_TCP_OVER_UDP_SERVER
#include "TcpOverUdpServer/interface.h"
#endif

#ifdef INCLUDE_UDP_STATELESS_SOCKET
#include "UdpStatelessSocket/interface.h"
#endif

#ifdef INCLUDE_RAWSOCKET
#include "RawSocket/interface.h"
#endif

#ifdef INCLUDE_BRIDGE
#include "Bridge/interface.h"
#endif

#ifdef INCLUDE_SNIFF_ROUTER
#include "SniffRouter/interface.h"
#endif

#ifdef INCLUDE_WOLFSSL_SERVER
#include "tunnels/server/wolfssl/wolfssl_server.h"
#endif

#ifdef INCLUDE_WOLFSSL_CLIENT
#include "tunnels/client/wolfssl/wolfssl_client.h"
#endif

#ifdef INCLUDE_HTTP_SERVER
#include "HttpServer/interface.h"
#endif

#ifdef INCLUDE_HTTP_CLIENT
#include "HttpClient/interface.h"
#endif

#ifdef INCLUDE_SOCKS5_CLIENT
#include "Socks5Client/interface.h"
#endif

#ifdef INCLUDE_PROTOBUF_SERVER
#include "tunnels/server/protobuf/protobuf_server.h"
#endif

#ifdef INCLUDE_PROTOBUF_CLIENT
#include "tunnels/client/protobuf/protobuf_client.h"
#endif

#ifdef INCLUDE_REVERSE_SERVER
#include "ReverseServer/interface.h"
#endif

#ifdef INCLUDE_REVERSE_CLIENT
#include "ReverseClient/interface.h"
#endif

#ifdef INCLUDE_HEADER_SERVER
#include "HeaderServer/interface.h"
#endif

#ifdef INCLUDE_HEADER_CLIENT
#include "HeaderClient/interface.h"
#endif

#ifdef INCLUDE_OBFUSCATOR_CLIENT
#include "ObfuscatorClient/interface.h"
#endif

#ifdef INCLUDE_OBFUSCATOR_SERVER
#include "ObfuscatorServer/interface.h"
#endif

#ifdef INCLUDE_ENCRYPTION_CLIENT
#include "EncryptionClient/interface.h"
#endif

#ifdef INCLUDE_ENCRYPTION_SERVER
#include "EncryptionServer/interface.h"
#endif

#ifdef INCLUDE_PRECONNECT_SERVER
#include "tunnels/server/preconnect/preconnect_server.h"
#endif

#ifdef INCLUDE_PRECONNECT_CLIENT
#include "tunnels/client/preconnect/preconnect_client.h"
#endif

#ifdef INCLUDE_SOCKS_5_SERVER
#include "Socks5Server/interface.h"
#endif

#ifdef INCLUDE_REALITY_SERVER
#include "RealityServer/interface.h"
#endif

#ifdef INCLUDE_REALITY_CLIENT
#include "RealityClient/interface.h"
#endif

#ifdef INCLUDE_HALFDUPLEX_SERVER
#include "HalfDuplexServer/interface.h"
#endif

#ifdef INCLUDE_HALFDUPLEX_CLIENT
#include "HalfDuplexClient/interface.h"
#endif

#ifdef INCLUDE_BGP4_SERVER
#include "Bgp4Server/interface.h"
#endif

#ifdef INCLUDE_BGP4_CLIENT
#include "Bgp4Client/interface.h"
#endif

#ifdef INCLUDE_MUX_SERVER
#include "MuxServer/interface.h"
#endif

#ifdef INCLUDE_MUX_CLIENT
#include "MuxClient/interface.h"
#endif

#ifdef INCLUDE_DISTURBER
#include "Disturber/interface.h"
#endif

#ifdef INCLUDE_BLACKHOLE
#include "BlackHole/interface.h"
#endif

#ifdef INCLUDE_SPEEDLIMIT
#include "SpeedLimit/interface.h"
#endif

#ifdef INCLUDE_USER_CONTROLLER
#include "UserController/interface.h"
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

#ifdef INCLUDE_SPEEDTEST_CLIENT
    USING(SpeedTestClient);
#endif

#ifdef INCLUDE_SPEEDTEST_SERVER
    USING(SpeedTestServer);
#endif

#ifdef INCLUDE_AUTHENTICATION_CLIENT
    USING(AuthenticationClient);
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

#ifdef INCLUDE_PACKETS_TO_STREAM
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

#ifdef INCLUDE_TCP_UDP_LISTENER
    USING(TcpUdpListener);
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

#ifdef INCLUDE_TROJAN_CLIENT
    USING(TrojanClient);
#endif

#ifdef INCLUDE_TROJAN_SERVER
    USING(TrojanServer);
#endif

#ifdef INCLUDE_VLESS_SERVER
    USING(VlessServer);
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

#ifdef INCLUDE_TCPCONNECTOR
    USING(TcpConnector);
#endif

#ifdef INCLUDE_UDP_CONNECTOR
    USING(UdpConnector);
#endif

#ifdef INCLUDE_TCP_UDP_CONNECTOR
    USING(TcpUdpConnector);
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

#ifdef INCLUDE_USER_CONTROLLER
    USING(UserController);
#endif
}
