"""Shared mechanics for the router_dns_chain_* probe cases: a loopback UDP DNS stub, a TCP echo peer, a
SOCKS5 CONNECT client and a log reader. Scenario inputs, expectations and verdicts stay in each case's
probe.py. Imported from a sibling link of the private run directory; never writes bytecode."""
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True

HOST = "127.0.0.1"
QTYPE_A = 1
QTYPE_AAAA = 28
RCODE_NXDOMAIN = 3


def parse_query(data):
    """Return (txid, flags, qname, qtype, qclass) of a DNS query, or None when malformed."""
    if len(data) < 12:
        return None
    txid, flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount < 1:
        return None
    labels = []
    offset = 12
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(data):
            return None
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return txid, flags, ".".join(labels).lower(), qtype, qclass, data[12:offset + 4]


def build_response(txid, question, rcode, answers):
    """A response with RD/RA set, one copied question and A answers (compressed name pointer)."""
    flags = 0x8180 | rcode
    body = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0) + question
    for address in answers:
        body += struct.pack("!HHHIH", 0xC00C, QTYPE_A, 1, 60, 4) + socket.inet_aton(address)
    return body


class DnsStub:
    """UDP DNS servers on loopback ports. `records` maps lowercased names to one IPv4 address; other A
    names get NXDOMAIN and AAAA gets NOERROR with no answers. `silent` records queries but never answers."""

    def __init__(self, ports, records, silent=False):
        self.records = dict(records)
        self.silent = silent
        self.queries = []
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.sockets = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((HOST, port))
            sock.settimeout(0.1)
            self.sockets.append(sock)
        self.threads = [threading.Thread(target=self._serve, args=(sock,), daemon=True) for sock in self.sockets]
        for thread in self.threads:
            thread.start()

    def _serve(self, sock):
        port = sock.getsockname()[1]
        while not self.stopping.is_set():
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            parsed = parse_query(data)
            with self.lock:
                self.queries.append({"port": port, "peer": peer, "parsed": parsed, "size": len(data)})
            if parsed is None or self.silent:
                continue
            txid, _, qname, qtype, _, question = parsed
            if qtype == QTYPE_A and qname in self.records:
                reply = build_response(txid, question, 0, [self.records[qname]])
            elif qtype == QTYPE_A:
                reply = build_response(txid, question, RCODE_NXDOMAIN, [])
            else:
                reply = build_response(txid, question, 0, [])
            sock.sendto(reply, peer)

    def snapshot(self):
        with self.lock:
            return list(self.queries)

    def close(self):
        self.stopping.set()
        for thread in self.threads:
            thread.join(2)
        for sock in self.sockets:
            sock.close()


class EchoServer:
    """TCP echo peer on one loopback address; records the local address each accepted connection hit."""

    def __init__(self, address, port):
        self.accepted = []
        self.lock = threading.Lock()
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((address, port))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stopping.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.accepted.append(conn.getsockname()[0])
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            conn.settimeout(5)
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        return
                    conn.sendall(data)
            except OSError:
                return

    def snapshot(self):
        with self.lock:
            return list(self.accepted)

    def close(self):
        self.stopping.set()
        self.thread.join(2)
        self.listener.close()


def _exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def socks_greet(proxy_port, deadline):
    """Connect and finish the no-auth greeting, retrying only until the listener is ready."""
    while True:
        sock = socket.socket()
        sock.settimeout(5)
        try:
            sock.connect((HOST, proxy_port))
            sock.sendall(b"\x05\x01\x00")
            if _exact(sock, 2) != b"\x05\x00":
                raise ConnectionError("SOCKS5 greeting rejected")
            return sock
        except (OSError, ConnectionError):
            sock.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def socks_connect_domain(proxy_port, domain, port, payload, timeout=10):
    """CONNECT by domain, wait for the reply like curl/browsers do, then send `payload`.
    Returns (reply_code or None on EOF before a reply, echoed bytes or None)."""
    deadline = time.monotonic() + timeout
    with socks_greet(proxy_port, deadline) as sock:
        name = domain.encode("ascii")
        request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port)
        sock.sendall(request)
        try:
            head = _exact(sock, 4)
            if head is None:
                return None, None
            atyp = head[3]
            if atyp == 1:
                tail = _exact(sock, 6)
            elif atyp == 4:
                tail = _exact(sock, 18)
            elif atyp == 3:
                size = _exact(sock, 1)
                tail = None if size is None else _exact(sock, size[0] + 2)
            else:
                raise AssertionError(f"unexpected SOCKS reply address type {atyp}")
            if tail is None or head[1] != 0:
                return head[1], None
            sock.sendall(payload)
            return 0, _exact(sock, len(payload))
        except ConnectionResetError:
            return None, None


def read_logs():
    """Concatenated runtime logs of this run (console capture plus the per-logger files)."""
    text = ""
    for path in [Path("stdout.log"), *sorted(Path("log").glob("*.log"))]:
        try:
            text += path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    return text


def wait_for_log(pattern, timeout=10):
    """Return the first match of `pattern` in the runtime logs, or None after `timeout` seconds."""
    regex = re.compile(pattern)
    deadline = time.monotonic() + timeout
    while True:
        match = regex.search(read_logs())
        if match is not None or time.monotonic() >= deadline:
            return match
        time.sleep(0.05)
