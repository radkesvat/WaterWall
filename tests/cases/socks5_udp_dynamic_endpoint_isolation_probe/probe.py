#!/usr/bin/env python3

import socket
import struct
import threading
import time


HOST = "127.0.0.1"
PROXY_PORT = 24700
ECHO_PORT = 24701
TIMEOUT = 0.45


def fail(message):
    raise AssertionError(message)


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            fail("SOCKS control connection closed while reading a reply")
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


def udp_associate(sock, requested_ip="0.0.0.0"):
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        fail("SOCKS server did not accept no-authentication")
    sock.sendall(b"\x05\x03\x00\x01" + socket.inet_aton(requested_ip) + b"\x00\x00")
    return read_socks_reply(sock)


def wrap_udp(payload):
    return b"\x00\x00\x00\x01" + socket.inet_aton(HOST) + struct.pack("!H", ECHO_PORT) + payload


def unwrap_udp(packet, expected_payload):
    if len(packet) < 10 or packet[:4] != b"\x00\x00\x00\x01":
        fail(f"malformed SOCKS UDP response: {packet!r}")
    address = socket.inet_ntoa(packet[4:8])
    port = struct.unpack("!H", packet[8:10])[0]
    if (address, port) != (HOST, ECHO_PORT):
        fail(f"SOCKS UDP response came from wrong target {(address, port)}")
    if packet[10:] != expected_payload:
        fail("SOCKS UDP response payload changed")


def expect_echo(sock, endpoint, payload):
    sock.sendto(wrap_udp(payload), endpoint)
    packet, source = sock.recvfrom(65535)
    if source[0] != HOST or source[1] != endpoint[1]:
        fail(f"SOCKS UDP response came from unexpected relay source {source}")
    unwrap_udp(packet, payload)


def expect_no_response(sock, endpoint, payload):
    sock.sendto(wrap_udp(payload), endpoint)
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        try:
            packet, source = sock.recvfrom(65535)
        except socket.timeout:
            return
        if source[0] == HOST and source[1] == endpoint[1]:
            fail(f"unauthorized UDP use received a relay response: {packet!r}")
    return


class EchoServer:
    def __init__(self):
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((HOST, ECHO_PORT))
                sock.settimeout(0.1)
                self.ready.set()
                while not self.stop.is_set():
                    try:
                        payload, peer = sock.recvfrom(65535)
                    except socket.timeout:
                        continue
                    sock.sendto(payload, peer)
        except BaseException as error:  # Propagate setup errors into the probe.
            self.error = error
            self.ready.set()

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(2.0):
            fail("UDP echo target did not start")
        if self.error is not None:
            raise self.error
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(2.0)
        if self.thread.is_alive():
            fail("UDP echo target did not stop")
        if self.error is not None:
            raise self.error


def main():
    with EchoServer():
        control_a = connect_with_retry()
        control_b = connect_with_retry()
        udp_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_a.bind((HOST, 0))
        udp_b.bind((HOST, 0))
        udp_a.settimeout(TIMEOUT)
        udp_b.settimeout(TIMEOUT)

        try:
            rep_a, addr_a, port_a = udp_associate(control_a)
            rep_b, addr_b, port_b = udp_associate(control_b)
            if rep_a != 0 or rep_b != 0:
                fail(f"legitimate UDP ASSOCIATE failed: A={rep_a}, B={rep_b}")
            if addr_a != HOST or addr_b != HOST or port_a == 0 or port_b == 0:
                fail("UDP ASSOCIATE did not return usable dynamic IPv4 relay endpoints")
            if port_a == port_b:
                fail("two simultaneous same-IP associations received the same relay port")

            endpoint_a = (addr_a, port_a)
            endpoint_b = (addr_b, port_b)
            expect_echo(udp_a, endpoint_a, b"association-a-first")
            expect_echo(udp_b, endpoint_b, b"association-b-first")

            # B has the same source IP but a different pinned source port.
            expect_no_response(udp_b, endpoint_a, b"cross-association-attempt")

            # The legacy shared TcpUdpListener UDP port is an ingress listener,
            # never a SOCKS relay authorization token.
            expect_no_response(udp_a, (HOST, PROXY_PORT), b"legacy-fixed-port-attempt")

            control_a.close()
            control_a = None
            # Endpoint close races are asynchronous; bounded retries prove the
            # old dynamic endpoint never authorizes traffic after control EOF.
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                udp_a.sendto(wrap_udp(b"association-a-after-close"), endpoint_a)
                try:
                    packet, source = udp_a.recvfrom(65535)
                except socket.timeout:
                    break
                if source[0] == HOST and source[1] == endpoint_a[1]:
                    time.sleep(0.05)
                    continue
            else:
                fail("closed association A still accepted UDP traffic")

            expect_echo(udp_b, endpoint_b, b"association-b-after-a-close")

            foreign = connect_with_retry()
            try:
                reply, _, _ = udp_associate(foreign, "127.0.0.2")
                if reply == 0:
                    fail("UDP ASSOCIATE accepted a concrete foreign peer IP hint")
            finally:
                foreign.close()
        finally:
            udp_a.close()
            udp_b.close()
            if control_a is not None:
                control_a.close()
            control_b.close()


if __name__ == "__main__":
    main()
