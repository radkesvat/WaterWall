#!/usr/bin/env python3

import socket
import struct
import threading
import time

HOST = "127.0.0.1"
PROXY_PORT = 24720
TARGET1_PORT = 24721
TARGET2_PORT = 24722
TARGET3_PORT = 24723
TARGET4_PORT = 24724


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


def unwrap_udp(packet, expected_payload, expected_port):
    if len(packet) < 10:
        fail(f"malformed SOCKS UDP response: {packet!r}")
    atyp = packet[3]
    if atyp == 1:
        address = socket.inet_ntoa(packet[4:8])
        port = struct.unpack("!H", packet[8:10])[0]
        data = packet[10:]
    else:
        fail(f"unexpected SOCKS UDP atyp {atyp}")
    if data != expected_payload:
        fail(f"payload mismatch: expected {expected_payload!r}, got {data!r}")
    if address != HOST or port != expected_port:
        fail(f"SOCKS UDP source mismatch: expected {HOST}:{expected_port}, got {address}:{port}")
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
    with TargetServer(TARGET1_PORT) as t1, TargetServer(TARGET2_PORT) as t2, TargetServer(
        TARGET3_PORT
    ) as t3, TargetServer(TARGET4_PORT) as t4:
        # Association 1
        ctrl_1 = connect_with_retry()
        _, r_addr_1, r_port_1 = udp_associate(ctrl_1)
        udp_1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_1.settimeout(2.0)

        # Send to Target 1 and Target 2 from Association 1
        udp_1.sendto(wrap_udp_ipv4(HOST, TARGET1_PORT, b"a1_to_t1"), (r_addr_1, r_port_1))
        sender_1_t1 = t1.get_last_sender()

        udp_1.sendto(wrap_udp_ipv4(HOST, TARGET2_PORT, b"a1_to_t2"), (r_addr_1, r_port_1))
        sender_1_t2 = t2.get_last_sender()

        if sender_1_t1[1] != sender_1_t2[1]:
            fail(f"Association 1 targets should share socket: {sender_1_t1[1]} vs {sender_1_t2[1]}")

        # Target 4 has not been selected by any line yet, so its datagram must be dropped.
        t4.reply_to(sender_1_t1, b"unregistered")
        udp_1.settimeout(0.25)
        try:
            packet, _ = udp_1.recvfrom(65535)
            fail(f"Association 1 received an unregistered-peer datagram: {packet!r}")
        except socket.timeout:
            pass
        udp_1.settimeout(2.0)

        # Association 2
        ctrl_2 = connect_with_retry()
        _, r_addr_2, r_port_2 = udp_associate(ctrl_2)
        udp_2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_2.settimeout(2.0)

        # Send to Target 3 and Target 4 from Association 2
        udp_2.sendto(wrap_udp_ipv4(HOST, TARGET3_PORT, b"a2_to_t3"), (r_addr_2, r_port_2))
        sender_2_t3 = t3.get_last_sender()

        udp_2.sendto(wrap_udp_ipv4(HOST, TARGET4_PORT, b"a2_to_t4"), (r_addr_2, r_port_2))
        sender_2_t4 = t4.get_last_sender()

        # Check Association 1 and Association 2 share the same socket port across non-overlapping peers
        if sender_2_t3[1] != sender_1_t1[1] or sender_2_t4[1] != sender_1_t1[1]:
            fail(
                f"Association 1 and 2 should share socket across distinct peers: {sender_1_t1[1]} vs {sender_2_t3[1]}"
            )

        # Association 2 now sends to Target 1 (collision with Association 1)
        udp_2.sendto(wrap_udp_ipv4(HOST, TARGET1_PORT, b"a2_to_t1"), (r_addr_2, r_port_2))
        sender_2_t1 = t1.get_last_sender()

        if sender_2_t1[1] == sender_1_t1[1]:
            fail(
                f"Association 2 to Target 1 should collide and use different port, but got {sender_2_t1[1]}"
            )

        # Replies
        t1.reply_to(sender_1_t1, b"rep_a1_t1")
        pkt, _ = udp_1.recvfrom(65535)
        unwrap_udp(pkt, b"rep_a1_t1", TARGET1_PORT)

        t2.reply_to(sender_1_t2, b"rep_a1_t2")
        pkt, _ = udp_1.recvfrom(65535)
        unwrap_udp(pkt, b"rep_a1_t2", TARGET2_PORT)

        t3.reply_to(sender_2_t3, b"rep_a2_t3")
        pkt, _ = udp_2.recvfrom(65535)
        unwrap_udp(pkt, b"rep_a2_t3", TARGET3_PORT)

        t4.reply_to(sender_2_t4, b"rep_a2_t4")
        pkt, _ = udp_2.recvfrom(65535)
        unwrap_udp(pkt, b"rep_a2_t4", TARGET4_PORT)

        t1.reply_to(sender_2_t1, b"rep_a2_t1")
        pkt, _ = udp_2.recvfrom(65535)
        unwrap_udp(pkt, b"rep_a2_t1", TARGET1_PORT)

        ctrl_1.close()
        ctrl_2.close()
        udp_1.close()
        udp_2.close()

    print("PASS: socks5_udp_packet_pool_probe passed")


if __name__ == "__main__":
    main()
