import socket
import ssl
import sys
import threading
import time


HOST = "127.0.0.1"
CLIENT_ENTRY_PORT = 23150
COVER_RELAY_PORT = 23152
TLS_SERVER_PORT = 23153
PROTECTED_SINK_PORT = 23154

REQUEST = b"post-handshake-request"
RESPONSE = b"post-handshake-response"
EXPECTED_TICKETS = 2
TLS_APPLICATION_HEADER = b"\x17\x03\x03"


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def recv_exact(sock, length):
    chunks = []
    while length:
        chunk = sock.recv(length)
        if not chunk:
            return None
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def recv_tls_record(sock):
    header = recv_exact(sock, 5)
    if header is None:
        return None
    body_length = int.from_bytes(header[3:5], "big")
    body = recv_exact(sock, body_length)
    if body is None:
        return None
    return header + body


def connect_with_retry(port):
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            return socket.create_connection((HOST, port), timeout=1.0)
        except OSError:
            time.sleep(0.05)
    fail(f"listener on port {port} did not open")


def start_tls_cover_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("server.crt", "server.key")
    context.num_tickets = EXPECTED_TICKETS

    state = {
        "ready": False,
        "handshakes": 0,
        "configured_tickets": context.num_tickets,
        "unexpected_plaintext": [],
        "errors": [],
    }
    stop = threading.Event()

    def handle(conn):
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                state["handshakes"] += 1
                tls.settimeout(0.2)
                while not stop.is_set():
                    try:
                        data = tls.recv(4096)
                    except socket.timeout:
                        continue
                    except (ssl.SSLError, OSError):
                        break
                    if not data:
                        break
                    state["unexpected_plaintext"].append(data)
        except (ssl.SSLError, OSError) as error:
            state["errors"].append(str(error))
            conn.close()

    def run():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((HOST, TLS_SERVER_PORT))
                listener.listen(1)
                listener.settimeout(0.2)
                state["ready"] = True
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except OSError as error:
            state["errors"].append(str(error))
            state["ready"] = True

    threading.Thread(target=run, daemon=True).start()
    return state, stop


def start_cover_relay():
    state = {"ready": False, "c2s": [], "s2c": [], "events": [], "errors": []}
    stop = threading.Event()
    lock = threading.Lock()

    def handle(client):
        try:
            server = socket.create_connection((HOST, TLS_SERVER_PORT), timeout=2.0)
        except OSError as error:
            state["errors"].append(f"TLS cover connect: {error}")
            client.close()
            return
        client.settimeout(5.0)
        server.settimeout(5.0)

        def pump(source, destination, direction):
            try:
                while not stop.is_set():
                    record = recv_tls_record(source)
                    if record is None:
                        break
                    with lock:
                        record_index = len(state[direction])
                        state[direction].append(record)
                        state["events"].append((direction, record_index))
                    destination.sendall(record)
            except (OSError, socket.timeout):
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        upstream = threading.Thread(target=pump, args=(client, server, "c2s"), daemon=True)
        downstream = threading.Thread(target=pump, args=(server, client, "s2c"), daemon=True)
        upstream.start()
        downstream.start()
        upstream.join(8.0)
        downstream.join(8.0)
        client.close()
        server.close()

    def run():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((HOST, COVER_RELAY_PORT))
                listener.listen(1)
                listener.settimeout(0.2)
                state["ready"] = True
                while not stop.is_set():
                    try:
                        client, _ = listener.accept()
                    except socket.timeout:
                        continue
                    threading.Thread(target=handle, args=(client,), daemon=True).start()
        except OSError as error:
            state["errors"].append(str(error))
            state["ready"] = True

    threading.Thread(target=run, daemon=True).start()
    return state, lock, stop


def start_protected_sink():
    state = {"ready": False, "connections": 0, "requests": [], "errors": []}
    stop = threading.Event()

    def run():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((HOST, PROTECTED_SINK_PORT))
                listener.listen(1)
                listener.settimeout(0.2)
                state["ready"] = True
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    state["connections"] += 1
                    with conn:
                        conn.settimeout(5.0)
                        request = recv_exact(conn, len(REQUEST))
                        state["requests"].append(request)
                        if request == REQUEST:
                            conn.sendall(RESPONSE)
        except OSError as error:
            state["errors"].append(str(error))
            state["ready"] = True

    threading.Thread(target=run, daemon=True).start()
    return state, stop


def wait_ready(states):
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if all(state["ready"] for state in states):
            return
        time.sleep(0.01)
    fail("post-handshake fixtures did not start")


def receive_response(sock):
    result = b""
    deadline = time.monotonic() + 5.0
    while len(result) < len(RESPONSE) and time.monotonic() < deadline:
        try:
            chunk = sock.recv(len(RESPONSE) - len(result))
        except socket.timeout:
            continue
        if not chunk:
            break
        result += chunk
    return result


def main():
    tls_state, tls_stop = start_tls_cover_server()
    relay_state, relay_lock, relay_stop = start_cover_relay()
    sink_state, sink_stop = start_protected_sink()
    wait_ready((tls_state, relay_state, sink_state))

    try:
        with connect_with_retry(CLIENT_ENTRY_PORT) as client:
            client.settimeout(0.2)
            client.sendall(REQUEST)
            response = receive_response(client)
            if response != RESPONSE:
                fail(f"protected response mismatch after ticket flight: {response!r}")

        deadline = time.monotonic() + 2.0
        snapshot = None
        while time.monotonic() < deadline:
            with relay_lock:
                if relay_state["c2s"] and relay_state["s2c"]:
                    c2s = list(relay_state["c2s"])
                    s2c = list(relay_state["s2c"])
                    events = list(relay_state["events"])
                    c2s_protected_indices = [
                        index
                        for index, record in enumerate(c2s)
                        if record[:3] == TLS_APPLICATION_HEADER
                    ]
                    if c2s_protected_indices:
                        final_client_record = ("c2s", c2s_protected_indices[-1])
                        if final_client_record in events:
                            final_client_event = events.index(final_client_record)
                            post_handshake_count = sum(
                                1
                                for event_index, (direction, record_index) in enumerate(events)
                                if direction == "s2c"
                                and event_index > final_client_event
                                and s2c[record_index][:3] == TLS_APPLICATION_HEADER
                            )
                            if post_handshake_count >= EXPECTED_TICKETS:
                                snapshot = (c2s, s2c, events)
                                break
            time.sleep(0.01)
        if snapshot is None:
            fail("cover relay did not capture the TLS handshake and ticket flight")
        c2s, s2c, events = snapshot

        c2s_protected_indices = [
            index for index, record in enumerate(c2s) if record[:3] == TLS_APPLICATION_HEADER
        ]
        if not c2s_protected_indices:
            fail("cover relay did not observe the client Finished record")
        final_client_record = ("c2s", c2s_protected_indices[-1])
        try:
            final_client_event = events.index(final_client_record)
        except ValueError:
            fail("client Finished was missing from the relay event stream")

        ticket_records = [
            s2c[record_index]
            for event_index, (direction, record_index) in enumerate(events)
            if direction == "s2c"
            and event_index > final_client_event
            and s2c[record_index][:3] == TLS_APPLICATION_HEADER
        ]
        if len(ticket_records) != EXPECTED_TICKETS:
            protected_lengths = [
                int.from_bytes(record[3:5], "big")
                for record in s2c
                if record[:3] == TLS_APPLICATION_HEADER
            ]
            fail(
                f"cover emitted {len(ticket_records)} protected post-handshake records; "
                f"expected {EXPECTED_TICKETS} tickets; protected server bodies={protected_lengths}, "
                f"events={events}"
            )
        if tls_state["configured_tickets"] != EXPECTED_TICKETS:
            fail("TLS fixture did not retain the requested ticket count")
        if tls_state["handshakes"] != 1:
            fail(f"TLS cover completed {tls_state['handshakes']} handshakes; expected 1")
        if tls_state["unexpected_plaintext"]:
            fail(f"Reality control escaped into cover TLS plaintext: {tls_state['unexpected_plaintext']!r}")
        if sink_state["connections"] != 1 or sink_state["requests"] != [REQUEST]:
            fail(f"protected sink state mismatch: {sink_state!r}")
        if tls_state["errors"] or relay_state["errors"] or sink_state["errors"]:
            fail(
                "fixture errors: "
                f"tls={tls_state['errors']}, relay={relay_state['errors']}, sink={sink_state['errors']}"
            )
        body_lengths = [int.from_bytes(record[3:5], "big") for record in ticket_records]
        print(f"observed {len(ticket_records)} emitted post-handshake ticket records: {body_lengths}")
    finally:
        sink_stop.set()
        relay_stop.set()
        tls_stop.set()


if __name__ == "__main__":
    main()
