import socket
import sys
import threading
import time


HOST = "127.0.0.1"
CLIENT_ENTRY_PORT = 25120
RELAY_PORT = 25121
REALITY_SERVER_PORT = 25122
PROTECTED_SINK_PORT = 25124
SAMPLE_COUNT = 12

REQUEST = b"wire-handoff-request"
RESPONSE = b"wire-handoff-response"

TLS_APPLICATION_HEADER = b"\x17\x03\x03"
TLS13_AES_128_GCM_SHA256 = 0x1301
CONTROL_MIN_BODY_LENGTH = 22
CONTROL_MAX_BODY_LENGTH = 1172


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


def start_protected_sink():
    state = {"ready": False, "connections": 0, "requests": [], "errors": []}
    stop = threading.Event()

    def handle(conn):
        try:
            conn.settimeout(5.0)
            request = recv_exact(conn, len(REQUEST))
            state["requests"].append(request)
            if request == REQUEST:
                conn.sendall(RESPONSE)
            while not stop.is_set() and conn.recv(4096):
                pass
        except (OSError, socket.timeout):
            pass
        finally:
            conn.close()

    def run():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((HOST, PROTECTED_SINK_PORT))
                listener.listen(SAMPLE_COUNT)
                listener.settimeout(0.2)
                state["ready"] = True
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    state["connections"] += 1
                    threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except OSError as error:
            state["errors"].append(str(error))
            state["ready"] = True

    threading.Thread(target=run, daemon=True).start()
    deadline = time.monotonic() + 2.0
    while not state["ready"]:
        if time.monotonic() >= deadline:
            fail("protected sink failed to start")
        time.sleep(0.01)
    if state["errors"]:
        fail(f"protected sink failed: {state['errors']}")
    return state, stop


def start_recording_relay():
    state = {"ready": False, "connections": [], "errors": []}
    stop = threading.Event()
    state_lock = threading.Lock()

    def handle(client, capture):
        try:
            server = socket.create_connection((HOST, REALITY_SERVER_PORT), timeout=2.0)
        except OSError as error:
            state["errors"].append(f"server connect: {error}")
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
                    with state_lock:
                        records = capture[direction]
                        record_index = len(records)
                        records.append(record)
                        capture["events"].append((direction, record_index))
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
                listener.bind((HOST, RELAY_PORT))
                listener.listen(SAMPLE_COUNT)
                listener.settimeout(0.2)
                state["ready"] = True
                while not stop.is_set():
                    try:
                        client, _ = listener.accept()
                    except socket.timeout:
                        continue
                    capture = {"c2s": [], "s2c": [], "events": []}
                    with state_lock:
                        state["connections"].append(capture)
                    threading.Thread(target=handle, args=(client, capture), daemon=True).start()
        except OSError as error:
            state["errors"].append(str(error))
            state["ready"] = True

    threading.Thread(target=run, daemon=True).start()
    deadline = time.monotonic() + 2.0
    while not state["ready"]:
        if time.monotonic() >= deadline:
            fail("recording relay failed to start")
        time.sleep(0.01)
    if state["errors"]:
        fail(f"recording relay failed: {state['errors']}")
    return state, state_lock, stop


def selected_server_cipher(records):
    handshake = bytearray()
    for record in records:
        if record[0] == 0x14:
            break
        if record[0] == 0x16:
            handshake.extend(record[5:])

    offset = 0
    while offset + 4 <= len(handshake):
        message_type = handshake[offset]
        message_length = int.from_bytes(handshake[offset + 1 : offset + 4], "big")
        body_start = offset + 4
        body_end = body_start + message_length
        if body_end > len(handshake):
            break
        if message_type == 0x02:
            body = handshake[body_start:body_end]
            if len(body) < 35:
                fail("truncated ServerHello")
            session_length = body[34]
            cipher_offset = 35 + session_length
            if cipher_offset + 2 > len(body):
                fail("truncated ServerHello cipher suite")
            return int.from_bytes(body[cipher_offset : cipher_offset + 2], "big")
        offset = body_end
    fail("wire probe did not observe a complete plaintext ServerHello")


def protected_records(records, direction):
    ccs_index = next(
        (index for index, record in enumerate(records) if record[0] == 0x14),
        None,
    )
    if ccs_index is None:
        fail(f"{direction} did not emit a compatibility ChangeCipherSpec")
    protected = records[ccs_index + 1 :]
    if not protected:
        fail(f"{direction} did not emit protected TLS 1.3 records")
    for record in protected:
        if record[:3] != TLS_APPLICATION_HEADER:
            fail(f"{direction} emitted a non-TLS-1.3 protected header: {record[:5].hex()}")
        body_length = int.from_bytes(record[3:5], "big")
        if len(record) != body_length + 5:
            fail(f"{direction} emitted a truncated TLS record")
    return protected, ccs_index + 1


def event_position(events, direction, record_index):
    try:
        return events.index((direction, record_index))
    except ValueError:
        fail(f"missing {direction} record {record_index} from relay event stream")


def validate_sample(capture, sample_index):
    c2s = capture["c2s"]
    s2c = capture["s2c"]
    events = capture["events"]

    cipher = selected_server_cipher(s2c)
    if cipher != TLS13_AES_128_GCM_SHA256:
        fail(
            f"sample {sample_index} selected cipher 0x{cipher:04x}; "
            f"expected 0x{TLS13_AES_128_GCM_SHA256:04x}"
        )

    c2s_protected, c2s_offset = protected_records(c2s, "client")
    s2c_protected, s2c_offset = protected_records(s2c, "server")
    if len(c2s_protected) < 4:
        fail(
            f"sample {sample_index} exposed only {len(c2s_protected)} client protected records; "
            "expected Finished, REQUEST, CONFIRM, and application data"
        )
    if len(s2c_protected) < 4:
        fail(
            f"sample {sample_index} exposed only {len(s2c_protected)} server protected records; "
            "expected handshake, post-handshake cover, ACK, and application data"
        )

    request_record = c2s_protected[-3]
    confirm_record = c2s_protected[-2]
    client_application = c2s_protected[-1]
    ack_record = s2c_protected[-2]
    server_application = s2c_protected[-1]

    expected_client_body = len(REQUEST) + 1 + 16
    expected_server_body = len(RESPONSE) + 1 + 16
    if int.from_bytes(client_application[3:5], "big") != expected_client_body:
        fail(f"sample {sample_index} did not place client application data after CONFIRM")
    if int.from_bytes(server_application[3:5], "big") != expected_server_body:
        fail(f"sample {sample_index} did not place server application data after ACK")

    controls = (request_record, ack_record, confirm_record)
    for name, record in zip(("REQUEST", "ACK", "CONFIRM"), controls):
        body_length = int.from_bytes(record[3:5], "big")
        if record[:3] != TLS_APPLICATION_HEADER:
            fail(f"sample {sample_index} {name} is not a TLS 1.3 application record")
        if not CONTROL_MIN_BODY_LENGTH <= body_length <= CONTROL_MAX_BODY_LENGTH:
            fail(
                f"sample {sample_index} {name} body length {body_length} is outside "
                f"{CONTROL_MIN_BODY_LENGTH}..{CONTROL_MAX_BODY_LENGTH}"
            )

    request_index = c2s_offset + len(c2s_protected) - 3
    ack_index = s2c_offset + len(s2c_protected) - 2
    request_event = event_position(events, "c2s", request_index)
    ack_event = event_position(events, "s2c", ack_index)
    if request_event >= ack_event:
        fail(f"sample {sample_index} ACK appeared before the client REQUEST")

    ack_protected_index = len(s2c_protected) - 2
    if ack_protected_index < 2:
        fail(
            f"sample {sample_index} ACK was not preceded by both protected handshake "
            "and post-handshake cover records"
        )
    if sample_index == 0:
        cover_lengths = [
            int.from_bytes(record[3:5], "big")
            for record in s2c_protected[:ack_protected_index]
        ]
        print(f"genuine cover-handshake prefix body lengths: {cover_lengths}")

    wire = b"".join(c2s + s2c)
    exposed_markers = (
        b"HANDOFF_REQUEST",
        b"HANDOFF_ACK",
        b"HANDOFF_CONFIRM",
        REQUEST,
        RESPONSE,
    )
    if any(marker in wire for marker in exposed_markers):
        fail(f"sample {sample_index} exposed a plaintext handoff/application marker")

    return [int.from_bytes(record[3:5], "big") for record in controls]


def main():
    sink_state, sink_stop = start_protected_sink()
    relay_state, relay_lock, relay_stop = start_recording_relay()
    control_lengths = []

    try:
        for sample_index in range(SAMPLE_COUNT):
            with connect_with_retry(CLIENT_ENTRY_PORT) as client:
                client.settimeout(0.2)
                client.sendall(REQUEST)
                response = receive_response(client)
                if response != RESPONSE:
                    fail(f"sample {sample_index} protected response mismatch: {response!r}")

                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    with relay_lock:
                        if len(relay_state["connections"]) > sample_index:
                            capture = relay_state["connections"][sample_index]
                            if capture["c2s"] and capture["s2c"]:
                                snapshot = {
                                    "c2s": list(capture["c2s"]),
                                    "s2c": list(capture["s2c"]),
                                    "events": list(capture["events"]),
                                }
                                break
                    time.sleep(0.01)
                else:
                    fail(f"sample {sample_index} relay capture did not complete")

                control_lengths.extend(validate_sample(snapshot, sample_index))

        if len(set(control_lengths)) < 2:
            fail(f"all {len(control_lengths)} authenticated handoff controls used one body length")
        if sink_state["connections"] != SAMPLE_COUNT:
            fail(
                f"protected chain opened {sink_state['connections']} times; "
                f"expected {SAMPLE_COUNT}"
            )
        if sink_state["requests"] != [REQUEST] * SAMPLE_COUNT:
            fail(f"protected sink observed unexpected requests: {sink_state['requests']!r}")
        if relay_state["errors"]:
            fail(f"recording relay errors: {relay_state['errors']}")
        print(
            f"observed {SAMPLE_COUNT} authenticated TLS 1.3 handoffs, "
            f"{len(control_lengths)} controls, and {len(set(control_lengths))} public body lengths"
        )
    finally:
        relay_stop.set()
        sink_stop.set()


if __name__ == "__main__":
    main()
