import socket
import sys
import threading
import time


HOST = "127.0.0.1"
CLIENT_ENTRY_PORT = 43210
RELAY_PORT = 43211
REALITY_SERVER_PORT = 43212
PROTECTED_SINK_PORT = 43214
REQUEST = b"reality-v2-original-request"
RESPONSE = b"reality-v2-protected-response"


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_tls_record(sock):
    header = recv_exact(sock, 5)
    if header is None:
        return None
    body = recv_exact(sock, int.from_bytes(header[3:5], "big"))
    if body is None:
        return None
    return header + body


def start_protected_sink():
    state = {"ready": False, "connections": 0, "payloads": []}
    response_sent = threading.Event()
    stop = threading.Event()

    def run():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((HOST, PROTECTED_SINK_PORT))
            listener.listen(4)
            listener.settimeout(0.2)
            state["ready"] = True
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                state["connections"] += 1
                with conn:
                    conn.settimeout(2.0)
                    payload = b""
                    while len(payload) < len(REQUEST):
                        try:
                            chunk = conn.recv(len(REQUEST) - len(payload))
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        payload += chunk
                    state["payloads"].append(payload)
                    if state["connections"] == 1 and payload == REQUEST:
                        response_sent.set()
                        try:
                            conn.sendall(RESPONSE)
                        except OSError:
                            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2.0
    while not state["ready"]:
        if time.monotonic() >= deadline:
            fail("protected sink failed to start")
        time.sleep(0.01)
    return state, response_sent, stop


def start_recording_relay(response_sent):
    state = {
        "ready": False,
        "connections": 0,
        "c2s_record": None,
        "s2c_record": None,
    }
    captured_c2s = threading.Event()
    captured_s2c = threading.Event()
    reflected = threading.Event()
    substituted = threading.Event()
    stop = threading.Event()

    def handle(client, connection_index):
        try:
            server = socket.create_connection((HOST, REALITY_SERVER_PORT), timeout=2.0)
        except OSError:
            client.close()
            return

        client.settimeout(4.0)
        server.settimeout(4.0)
        server_write_lock = threading.Lock()

        def upstream():
            application_records = 0
            try:
                while True:
                    record = recv_tls_record(client)
                    if record is None:
                        break
                    if record[0] == 0x17:
                        application_records += 1

                    outgoing = record
                    if connection_index == 0 and application_records == 2:
                        state["c2s_record"] = record
                        captured_c2s.set()
                    elif connection_index == 1 and application_records == 2:
                        if not captured_c2s.wait(2.0):
                            break
                        outgoing = state["c2s_record"]
                        substituted.set()

                    with server_write_lock:
                        server.sendall(outgoing)
            except (OSError, socket.timeout):
                pass
            finally:
                try:
                    server.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        def downstream():
            try:
                while True:
                    record = recv_tls_record(server)
                    if record is None:
                        break
                    if connection_index == 0 and response_sent.is_set() and record[0] == 0x17 and not captured_s2c.is_set():
                        state["s2c_record"] = record
                        captured_s2c.set()
                        client.sendall(record)
                        with server_write_lock:
                            server.sendall(record)
                        reflected.set()
                        continue
                    client.sendall(record)
            except (OSError, socket.timeout):
                pass
            finally:
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        up = threading.Thread(target=upstream, daemon=True)
        down = threading.Thread(target=downstream, daemon=True)
        up.start()
        down.start()
        up.join(6.0)
        down.join(6.0)
        client.close()
        server.close()

    def run():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((HOST, RELAY_PORT))
            listener.listen(4)
            listener.settimeout(0.2)
            state["ready"] = True
            while not stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                index = state["connections"]
                state["connections"] += 1
                threading.Thread(target=handle, args=(client, index), daemon=True).start()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2.0
    while not state["ready"]:
        if time.monotonic() >= deadline:
            fail("recording relay failed to start")
        time.sleep(0.01)
    return state, captured_c2s, captured_s2c, reflected, substituted, stop


def connect_with_retry(port):
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            return socket.create_connection((HOST, port), timeout=1.0)
        except OSError:
            time.sleep(0.05)
    fail(f"Waterwall listener on port {port} did not open")


def receive_response(sock):
    result = b""
    deadline = time.monotonic() + 4.0
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
    sink_state, response_sent, sink_stop = start_protected_sink()
    relay_state, captured_c2s, captured_s2c, reflected, substituted, relay_stop = start_recording_relay(response_sent)

    with connect_with_retry(CLIENT_ENTRY_PORT) as original:
        original.settimeout(0.2)
        original.sendall(REQUEST)
        response = receive_response(original)
        if response != RESPONSE:
            fail(f"original protected response mismatch: {response!r}")
        if not captured_c2s.wait(2.0):
            fail("relay did not capture the original client-to-server Reality record")
        if not captured_s2c.wait(2.0):
            fail("relay did not capture the original server-to-client Reality record")
        if not reflected.wait(2.0):
            fail("relay did not reflect the downstream Reality record upstream")

    with connect_with_retry(REALITY_SERVER_PORT) as direct:
        direct.sendall(relay_state["c2s_record"])
        try:
            direct.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        time.sleep(0.3)

    with connect_with_retry(CLIENT_ENTRY_PORT) as replayed:
        replayed.settimeout(0.2)
        replayed.sendall(REQUEST)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not substituted.is_set():
            try:
                if replayed.recv(4096) == b"":
                    break
            except socket.timeout:
                pass
        if not substituted.is_set():
            fail("relay did not substitute the captured record on the fresh TLS connection")

    time.sleep(0.8)
    relay_stop.set()
    sink_stop.set()

    if sink_state["connections"] != 1:
        fail(f"protected chain opened {sink_state['connections']} times; expected exactly the original connection")
    if sink_state["payloads"] != [REQUEST]:
        fail(f"protected sink observed unexpected payloads: {sink_state['payloads']!r}")
    if relay_state["connections"] < 2:
        fail("relay did not observe both full TLS connections")


if __name__ == "__main__":
    main()
