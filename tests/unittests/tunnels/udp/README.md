# UDP socket association coverage

The [UdpConnector socket-pool fixture](udpconnector_socket_pool_test.c) covers
queue publication before Pause and an exact shared initialization/DNS capacity
ceiling with empty datagrams. Its binding table and real socket peers also cover
collision, worker/instance isolation, late replies, retirement and packet-mode
multi-destination ownership. The source lists the exact CTest selection.
