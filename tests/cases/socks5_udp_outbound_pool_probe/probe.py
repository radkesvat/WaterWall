#!/usr/bin/env python3

import socket
import struct
import threading
import time

HOST = "127.0.0.1"
PROXY_PORT = 24710
TARGET1_PORT = 24711
TARGET2_PORT = 24712
TARGET3_PORT = 24713
TIMEOUT = 1.0


def fail(message):
    raise AssertionError(message)


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            fail("SOCKS control connection closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


def connect_with_retry():
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((HOST, 0))
            sock.settimeout(1.0)
            sock.connect((HOST, PROXY_PORT))
            return sock
        except OSError:
            sock.close()
            time.sleep(0.05)
    fail("SOCKS TCP listener did not open")


def read_socks_reply(sock):
    header = recv_exact(sock, 4)
    if header[0] != 5 or header[2] != 0:
        fail(f"malformed SOCKS reply header: {header!r}")
    atyp = header[3]
    if atyp == 1:
        address = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 4:
        address = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    elif atyp == 3:
        address = recv_exact(sock, recv_exact(sock, 1)[0]).decode("ascii")
    else:
        fail(f"unsupported SOCKS reply address type {atyp}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return header[1], address, port


def udp_associate(sock):
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        fail("SOCKS server did not accept no-authentication")
    sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply = read_socks_reply(sock)
    if reply[0] != 0:
        fail(f"SOCKS UDP ASSOCIATE failed with reply code {reply[0]}")
    return reply


def wrap_udp_ipv4(target_host, target_port, payload):
    return b"\x00\x00\x00\x01" + socket.inet_aton(target_host) + struct.pack("!H", target_port) + payload


def wrap_udp_domain(domain_name, target_port, payload):
    domain_bytes = domain_name.encode("ascii")
    return (
        b"\x00\x00\x00\x03"
        + struct.pack("!B", len(domain_bytes))
        + domain_bytes
        + struct.pack("!H", target_port)
        + payload
    )


def unwrap_udp(packet, expected_payload, expected_port, expected_addresses=(HOST,)):
    if len(packet) < 10:
        fail(f"malformed SOCKS UDP response: {packet!r}")
    atyp = packet[3]
    if atyp == 1:
        address = socket.inet_ntoa(packet[4:8])
        port = struct.unpack("!H", packet[8:10])[0]
        data = packet[10:]
    elif atyp == 3:
        dlen = packet[4]
        address = packet[5 : 5 + dlen].decode("ascii")
        port = struct.unpack("!H", packet[5 + dlen : 7 + dlen])[0]
        data = packet[7 + dlen :]
    else:
        fail(f"unexpected SOCKS UDP atyp {atyp}")
    if data != expected_payload:
        fail(f"payload mismatch: expected {expected_payload!r}, got {data!r}")
    if address not in expected_addresses or port != expected_port:
        fail(
            f"SOCKS UDP source mismatch: expected {expected_addresses!r}:{expected_port}, "
            f"got {address}:{port}"
        )
    return address, port


class TargetServer:
    def __init__(self, port):
        self.port = port
        self.sock = None
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.last_sender = None
        self.last_payload = None
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            self.sock = s
            s.bind((HOST, self.port))
            s.settimeout(0.1)
            self.ready.set()
            while not self.stop.is_set():
                try:
                    payload, peer = s.recvfrom(65535)
                    with self.lock:
                        self.last_sender = peer
                        self.last_payload = payload
                except socket.timeout:
                    continue

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(2.0):
            fail(f"Target server on {self.port} did not start")
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(2.0)

    def get_last_sender(self, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if self.last_sender is not None:
                    sender = self.last_sender
                    self.last_sender = None
                    return sender
            time.sleep(0.02)
        fail(f"Target on {self.port} timed out waiting for datagram")

    def reply_to(self, peer, payload):
        self.sock.sendto(payload, peer)


def main():
    with TargetServer(TARGET1_PORT) as t1, TargetServer(TARGET2_PORT) as t2, TargetServer(TARGET3_PORT) as t3:
        # Client A to Target 1
        ctrl_a = connect_with_retry()
        rep_a, r_addr_a, r_port_a = udp_associate(ctrl_a)
        udp_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_a.settimeout(2.0)
        udp_a.sendto(wrap_udp_ipv4(HOST, TARGET1_PORT, b"msg_from_a"), (r_addr_a, r_port_a))
        sender_a = t1.get_last_sender()

        # Client B to Target 2
        ctrl_b = connect_with_retry()
        rep_b, r_addr_b, r_port_b = udp_associate(ctrl_b)
        udp_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_b.settimeout(2.0)
        udp_b.sendto(wrap_udp_ipv4(HOST, TARGET2_PORT, b"msg_from_b"), (r_addr_b, r_port_b))
        sender_b = t2.get_last_sender()

        # 1. Verify outbound port sharing across distinct targets
        if sender_a[1] != sender_b[1]:
            fail(
                f"Clients A and B should share outbound socket, but got ports {sender_a[1]} and {sender_b[1]}"
            )

        # 2. Reverse order replies
        t2.reply_to(sender_b, b"reply_for_b")
        t1.reply_to(sender_a, b"reply_for_a")

        pkt_b, _ = udp_b.recvfrom(65535)
        unwrap_udp(pkt_b, b"reply_for_b", TARGET2_PORT)

        pkt_a, _ = udp_a.recvfrom(65535)
        unwrap_udp(pkt_a, b"reply_for_a", TARGET1_PORT)

        # An endpoint without a registered line cannot claim traffic on the shared socket.
        t3.reply_to(sender_a, b"unsolicited")
        for client, label in ((udp_a, "A"), (udp_b, "B")):
            client.settimeout(0.25)
            try:
                packet, _ = client.recvfrom(65535)
                fail(f"Client {label} received an unregistered-peer datagram: {packet!r}")
            except socket.timeout:
                pass

        # 3. Client C to Target 1 (collision on same peer)
        ctrl_c = connect_with_retry()
        rep_c, r_addr_c, r_port_c = udp_associate(ctrl_c)
        udp_c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_c.settimeout(2.0)
        udp_c.sendto(wrap_udp_ipv4(HOST, TARGET1_PORT, b"msg_from_c"), (r_addr_c, r_port_c))
        sender_c = t1.get_last_sender()

        if sender_c[1] == sender_a[1]:
            fail(f"Client C to Target 1 should collide and use different port, but got {sender_c[1]}")

        t1.reply_to(sender_c, b"reply_for_c")
        pkt_c, _ = udp_c.recvfrom(65535)
        unwrap_udp(pkt_c, b"reply_for_c", TARGET1_PORT)

        # 4. Client D uses a domain that resolves to A/C's literal wire peer.
        ctrl_d = connect_with_retry()
        rep_d, r_addr_d, r_port_d = udp_associate(ctrl_d)
        udp_d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_d.settimeout(2.0)
        udp_d.sendto(wrap_udp_domain("localhost", TARGET1_PORT, b"msg_from_d"), (r_addr_d, r_port_d))
        sender_d = t1.get_last_sender()

        if sender_d[1] == sender_a[1] or sender_d[1] == sender_c[1]:
            fail(
                f"Client D should collide with A and C, but got port {sender_d[1]} (A={sender_a[1]}, C={sender_c[1]})"
            )

        t1.reply_to(sender_d, b"reply_for_d")
        pkt_d, _ = udp_d.recvfrom(65535)
        unwrap_udp(pkt_d, b"reply_for_d", TARGET1_PORT, (HOST, "localhost"))

        ctrl_a.close()
        ctrl_b.close()
        ctrl_c.close()
        ctrl_d.close()
        udp_a.close()
        udp_b.close()
        udp_c.close()
        udp_d.close()

    print("PASS: socks5_udp_outbound_pool_probe passed")


if __name__ == "__main__":
    main()
