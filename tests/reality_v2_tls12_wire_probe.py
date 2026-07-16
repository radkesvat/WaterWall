import socket
import sys
import threading
import time
from pathlib import Path


HOST = "127.0.0.1"
CASE_NAME = Path.cwd().name
PROFILE = "tls13" if "tls13" in CASE_NAME else "chacha" if "chacha" in CASE_NAME else "cbc" if "cbc" in CASE_NAME else "gcm"
BASE_PORT = {"gcm": 43300, "cbc": 43310, "chacha": 43320, "tls13": 43330}[PROFILE]
CLIENT_ENTRY_PORT = BASE_PORT
RELAY_PORT = BASE_PORT + 1
REALITY_SERVER_PORT = BASE_PORT + 2
PROTECTED_SINK_PORT = BASE_PORT + 4
REQUEST = b"keyless-wire-request"
RESPONSE = b"keyless-wire-response"
EXPECTED_CIPHER = {"gcm": 0xC02F, "cbc": 0xC013, "chacha": 0xCCA8, "tls13": 0x1301}[PROFILE]
ALERT_TYPE = 0x17 if PROFILE == "tls13" else 0x15
ALERT_BODY_LENGTH = 19 if PROFILE == "tls13" else 26 if PROFILE == "gcm" else 48 if PROFILE == "cbc" else 18


def application_body_length(payload_length):
    if PROFILE == "tls13":
        return payload_length + 1 + 16
    if PROFILE == "chacha":
        return payload_length + 16
    if PROFILE == "gcm":
        return 8 + payload_length + 16
    return 16 + ((payload_length + 20 + 1 + 15) // 16) * 16


TAKEOVER_BODY_LENGTHS = {
    application_body_length(payload_length)
    for payload_length in (1, len(REQUEST), len(RESPONSE))
}


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


def is_reality_application(record):
    return (
        record[:3] == b"\x17\x03\x03"
        and int.from_bytes(record[3:5], "big") in TAKEOVER_BODY_LENGTHS
    )


def is_reality_alert(record):
    return (
        record[0] == ALERT_TYPE
        and record[1:3] == b"\x03\x03"
        and int.from_bytes(record[3:5], "big") == ALERT_BODY_LENGTH
    )


def recv_up_to(sock, length):
    chunks = []
    received = 0
    while received < length:
        try:
            chunk = sock.recv(length - received)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def start_protected_sink():
    state = {"ready": False, "connections": 0, "payloads": []}
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
                    payload = recv_up_to(conn, len(REQUEST))
                    state["payloads"].append(payload)
                    if payload == REQUEST:
                        conn.sendall(RESPONSE)
                        if state["connections"] in (1, 3, 4):
                            # Keep the protected side open for client-normal
                            # close and for each corruption detector scenario.
                            recv_up_to(conn, 1)

    threading.Thread(target=run, daemon=True).start()
    deadline = time.monotonic() + 2.0
    while not state["ready"]:
        if time.monotonic() >= deadline:
            fail("protected sink failed to start")
        time.sleep(0.01)
    return state, stop


def start_recording_relay():
    state = {
        "ready": False,
        "connections": 0,
        "c2s_records": [],
        "s2c_records": [],
        "c2s_application": [],
        "s2c_application": [],
        "c2s_alerts": [],
        "s2c_alerts": [],
        "server_normal_s2c_records": [],
        "server_normal_s2c_application": [],
        "scenario_alerts": {
            index: {"c2s": [], "s2c": []} for index in range(7)
        },
        "direction_events": {index: [] for index in range(7)},
        "immediate_application": [],
    }
    captured = threading.Event()
    reflected = threading.Event()
    mirrored = threading.Event()
    cross_replayed = threading.Event()
    reorder_first_forwarded = threading.Event()
    reorder_second_held = threading.Event()
    reordered = threading.Event()
    server_fatal = threading.Event()
    client_fatal = threading.Event()
    client_closed_without_server_fin = threading.Event()
    immediate_handshake = threading.Event()
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
        handshake_state = {
            "c2s_ccs": False,
            "s2c_ccs": False,
            "c2s_protected": False,
            "s2c_protected": False,
            "first_c2s_application": None,
        }

        def observe_immediate_handshake(direction, record):
            if connection_index != 6 or immediate_handshake.is_set():
                return
            if record[0] == 0x14:
                handshake_state[f"{direction}_ccs"] = True
            elif PROFILE == "tls13":
                if record[0] == 0x17:
                    handshake_state[f"{direction}_protected"] = True
            elif handshake_state[f"{direction}_ccs"]:
                handshake_state[f"{direction}_protected"] = True

            if handshake_state["c2s_protected"] and handshake_state["s2c_protected"]:
                immediate_handshake.set()

        def send_server(record):
            with server_write_lock:
                server.sendall(record)
            observe_immediate_handshake("c2s", record)

        def upstream():
            application_index = 0
            saw_eof = False
            try:
                while True:
                    record = recv_tls_record(client)
                    if record is None:
                        saw_eof = True
                        break
                    if connection_index == 0:
                        state["c2s_records"].append(record)

                    if is_reality_alert(record):
                        state["scenario_alerts"][connection_index]["c2s"].append(record)
                        state["direction_events"][connection_index].append("c2s_alert")
                        if connection_index == 0:
                            state["c2s_alerts"].append(record)
                        if connection_index == 3:
                            client_fatal.set()
                        send_server(record)
                        continue

                    if not is_reality_application(record):
                        send_server(record)
                        continue

                    application_index += 1
                    if handshake_state["first_c2s_application"] is None:
                        handshake_state["first_c2s_application"] = record
                    if connection_index == 0:
                        state["c2s_application"].append(record)
                        send_server(record)
                        if len(state["c2s_application"]) == 1:
                            captured.set()
                    elif connection_index in (1, 2, 3):
                        send_server(record)
                    elif connection_index == 4 and application_index == 1:
                        if not captured.wait(2.0):
                            break
                        cross_replayed.set()
                        send_server(state["c2s_application"][0])
                    elif connection_index == 5 and application_index == 1:
                        send_server(record)
                        reorder_first_forwarded.set()
                    elif connection_index == 5 and application_index == 2:
                        reorder_second_held.set()
                    elif connection_index == 5 and application_index == 3:
                        send_server(record)
                        reordered.set()
                        break
                    elif connection_index == 6:
                        if immediate_handshake.is_set():
                            state["immediate_application"].append(record)
                        send_server(record)
                    else:
                        send_server(record)
            except (OSError, socket.timeout):
                pass
            finally:
                if saw_eof:
                    state["direction_events"][connection_index].append("c2s_eof")
                try:
                    server.shutdown(socket.SHUT_WR)
                    if saw_eof:
                        state["direction_events"][connection_index].append("c2s_fin_forwarded")
                except OSError:
                    pass

        def downstream():
            application_count = 0
            corruption_sent = False
            saw_eof = False
            try:
                while True:
                    record = recv_tls_record(server)
                    if record is None:
                        saw_eof = True
                        break
                    if connection_index == 0:
                        state["s2c_records"].append(record)
                        if is_reality_alert(record):
                            state["s2c_alerts"].append(record)
                    elif connection_index == 1:
                        state["server_normal_s2c_records"].append(record)
                    if is_reality_alert(record):
                        state["scenario_alerts"][connection_index]["s2c"].append(record)
                        state["direction_events"][connection_index].append("s2c_alert")
                        if connection_index == 2:
                            server_fatal.set()

                    observe_immediate_handshake("s2c", record)
                    if connection_index == 0 and is_reality_application(record):
                        state["s2c_application"].append(record)
                        application_count += 1
                    elif connection_index == 1 and is_reality_application(record):
                        state["server_normal_s2c_application"].append(record)
                    elif connection_index == 2 and is_reality_application(record):
                        application_count += 1
                        if application_count == 1:
                            send_server(record)
                            reflected.set()
                    elif connection_index == 3 and is_reality_application(record):
                        if handshake_state["first_c2s_application"] is None:
                            break
                        if not corruption_sent:
                            client.sendall(handshake_state["first_c2s_application"])
                            corruption_sent = True
                            mirrored.set()
                        continue
                    elif (connection_index == 6 and immediate_handshake.is_set() and
                          is_reality_application(record)):
                        state["immediate_application"].append(record)
                    client.sendall(record)
                    if connection_index == 1 and is_reality_alert(record):
                        # Do not read/forward the server FIN yet. The client
                        # must close its transport from the authenticated alert
                        # alone, even if the peer withholds FIN indefinitely.
                        deadline = time.monotonic() + 2.0
                        while time.monotonic() < deadline:
                            if "c2s_eof" in state["direction_events"][connection_index]:
                                client_closed_without_server_fin.set()
                                break
                            time.sleep(0.01)
            except (OSError, socket.timeout):
                pass
            finally:
                if saw_eof:
                    state["direction_events"][connection_index].append("s2c_eof")
                try:
                    client.shutdown(socket.SHUT_WR)
                    if saw_eof:
                        state["direction_events"][connection_index].append("s2c_fin_forwarded")
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

    threading.Thread(target=run, daemon=True).start()
    deadline = time.monotonic() + 2.0
    while not state["ready"]:
        if time.monotonic() >= deadline:
            fail("recording relay failed to start")
        time.sleep(0.01)
    return (
        state,
        captured,
        reflected,
        mirrored,
        cross_replayed,
        reorder_first_forwarded,
        reorder_second_held,
        reordered,
        server_fatal,
        client_fatal,
        client_closed_without_server_fin,
        immediate_handshake,
        stop,
    )


def connect_with_retry(port):
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            return socket.create_connection((HOST, port), timeout=1.0)
        except OSError:
            time.sleep(0.05)
    fail(f"Waterwall listener on port {port} did not open")


def receive_exact_response(sock):
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


def drain_rejected_connection(sock, event):
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and not event.is_set():
        try:
            if sock.recv(4096) == b"":
                event.wait(max(0.0, deadline - time.monotonic()))
                break
        except ConnectionResetError:
            event.wait(max(0.0, deadline - time.monotonic()))
            break
        except socket.timeout:
            pass
    if not event.is_set():
        fail("relay did not perform the requested rejected-record substitution")


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
    fail("probe did not observe a complete plaintext ServerHello")


def validate_candidate_headers(records, expected_count, expected_body_length, direction):
    if len(records) != expected_count:
        fail(f"{direction} emitted {len(records)} candidate records; expected {expected_count}")
    for record in records:
        if record[:3] != b"\x17\x03\x03":
            fail(f"{direction} candidate has a non-TLS-1.2 application header: {record[:3].hex()}")
        body_length = int.from_bytes(record[3:5], "big")
        if body_length != expected_body_length or len(record) != body_length + 5:
            fail(f"{direction} candidate body length {body_length}; expected {expected_body_length}")


def validate_client_gcm_sequences(records):
    protected = False
    sequence = 0
    protected_records = 0
    for record in records:
        if record[0] == 0x14:
            if record[5:] != b"\x01":
                fail("client malformed ChangeCipherSpec")
            protected = True
            sequence = 0
            continue
        if not protected:
            continue
        body = record[5:]
        if len(body) < 24:
            fail("client protected GCM record is too short")
        explicit_nonce = int.from_bytes(body[:8], "big")
        if explicit_nonce != sequence:
            fail(
                f"client explicit nonce {explicit_nonce} did not continue TLS sequence {sequence}"
            )
        sequence += 1
        protected_records += 1
    if protected_records < 2:
        fail("client did not include both genuine and takeover protected records")


def validate_server_gcm_policy(records, candidate_records):
    protected = False
    tls_sequence = 0
    cover_values = []
    candidate_values = []
    candidate_ids = {id(record) for record in candidate_records}

    for record in records:
        if record[0] == 0x14:
            if record[5:] != b"\x01":
                fail("server malformed ChangeCipherSpec")
            protected = True
            tls_sequence = 0
            continue
        if not protected:
            continue
        body = record[5:]
        if len(body) < 24:
            fail("server protected GCM record is too short")
        value = int.from_bytes(body[:8], "big")
        if id(record) in candidate_ids:
            candidate_values.append(value)
        else:
            cover_values.append((tls_sequence, value))
        tls_sequence += 1

    if not cover_values or not candidate_values:
        fail("server did not include enough genuine and takeover GCM records")

    if all(value == sequence for sequence, value in cover_values):
        expected = cover_values[-1][0] + 1
        for value in candidate_values:
            if value != expected:
                fail(f"server sequence policy emitted {value}; expected {expected}")
            expected += 1
        return

    raw_cover_values = [value for _, value in cover_values]
    counter_pattern = len(raw_cover_values) >= 2 and all(
        current == previous + 1
        for previous, current in zip(raw_cover_values, raw_cover_values[1:])
    )
    if counter_pattern:
        expected = raw_cover_values[-1] + 1
        for value in candidate_values:
            if value != expected:
                fail(f"server counter policy emitted {value}; expected {expected}")
            expected += 1
        return

    # With one non-sequence sample, auto deliberately freezes the random policy.
    all_values = raw_cover_values + candidate_values
    if len(set(all_values)) != len(all_values):
        fail("server random policy repeated a visible explicit nonce")


def validate_cbc_structure(records, direction):
    protected = False
    protected_records = 0
    for record in records:
        if record[0] == 0x14:
            protected = True
            continue
        if not protected:
            continue
        body_length = int.from_bytes(record[3:5], "big")
        if body_length < 32 or (body_length - 16) % 16 != 0:
            fail(f"{direction} protected CBC body is not explicit-IV plus aligned ciphertext")
        protected_records += 1
    if protected_records < 2:
        fail(f"{direction} did not include both genuine and takeover protected records")


def validate_alerts(alerts, expected_count, scenario, direction):
    if len(alerts) != expected_count:
        fail(f"{scenario} emitted {len(alerts)} {direction} alerts; expected {expected_count}")
    for alert in alerts:
        if alert[0] != ALERT_TYPE or alert[1:3] != b"\x03\x03" or int.from_bytes(alert[3:5], "big") != ALERT_BODY_LENGTH:
            fail(f"{scenario} {direction} close alert has the wrong TLS shape: {alert[:5].hex()}")
        if alert[5:] in (b"\x01\x00", b"\x02\x14"):
            fail(f"{scenario} {direction} exposed a plaintext TLS alert")


def wait_for_direction_event(state, connection_index, event, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if event in state["direction_events"][connection_index]:
            return
        time.sleep(0.01)
    fail(f"connection {connection_index} did not observe {event}")


def validate_alert_before_eof(state, connection_index, direction, scenario):
    events = state["direction_events"][connection_index]
    alert = f"{direction}_alert"
    eof = f"{direction}_eof"
    if alert not in events or eof not in events or events.index(alert) > events.index(eof):
        fail(f"{scenario} did not place the {direction} alert before directional EOF: {events}")


def validate_wire_image(state):
    cipher = selected_server_cipher(state["s2c_records"])
    if cipher != EXPECTED_CIPHER:
        fail(f"ServerHello selected cipher 0x{cipher:04x}; expected 0x{EXPECTED_CIPHER:04x}")

    validate_alerts(state["c2s_alerts"], 0, "client-initiated close", "c2s")
    validate_alerts(state["s2c_alerts"], 0, "client-initiated close", "s2c")

    if PROFILE == "gcm":
        validate_candidate_headers(
            state["c2s_application"], 1, application_body_length(len(REQUEST)), "client"
        )
        validate_candidate_headers(
            state["s2c_application"], 1, application_body_length(len(RESPONSE)), "server"
        )
        validate_client_gcm_sequences(state["c2s_records"])
        validate_server_gcm_policy(
            state["s2c_records"], state["s2c_application"]
        )
        validate_server_gcm_policy(
            state["server_normal_s2c_records"],
            state["server_normal_s2c_application"] + state["scenario_alerts"][1]["s2c"],
        )
    else:
        if PROFILE in ("chacha", "tls13"):
            validate_candidate_headers(
                state["c2s_application"], 1, application_body_length(len(REQUEST)), "client"
            )
            validate_candidate_headers(
                state["s2c_application"], 1, application_body_length(len(RESPONSE)), "server"
            )
            return
        validate_candidate_headers(
            state["c2s_application"], 1, application_body_length(len(REQUEST)), "client"
        )
        validate_candidate_headers(
            state["s2c_application"], 1, application_body_length(len(RESPONSE)), "server"
        )
        validate_cbc_structure(state["c2s_records"], "client")
        validate_cbc_structure(state["s2c_records"], "server")
        validate_cbc_structure(state["server_normal_s2c_records"], "server-normal")
        visible_ivs = [
            record[5:21]
            for record in state["c2s_application"]
            + state["s2c_application"]
            + state["server_normal_s2c_application"]
            + state["scenario_alerts"][1]["s2c"]
        ]
        if len(set(visible_ivs)) != len(visible_ivs):
            fail("CBC takeover records repeated a visible IV")


def main():
    sink_state, sink_stop = start_protected_sink()
    (
        relay_state,
        captured,
        reflected,
        mirrored,
        cross_replayed,
        reorder_first_forwarded,
        reorder_second_held,
        reordered,
        server_fatal,
        client_fatal,
        client_closed_without_server_fin,
        immediate_handshake,
        relay_stop,
    ) = start_recording_relay()

    with connect_with_retry(CLIENT_ENTRY_PORT) as original:
        original.settimeout(0.2)
        original.sendall(REQUEST)
        response = receive_exact_response(original)
        if response != RESPONSE:
            fail(f"original protected response mismatch: {response!r}")
        if not captured.wait(2.0):
            fail("relay did not capture all original client Reality records")
    wait_for_direction_event(relay_state, 0, "c2s_eof")
    wait_for_direction_event(relay_state, 0, "s2c_eof")

    # A protected-side normal close produces one unacknowledged server alert
    # before server EOF. RealityClient consumes it and emits no response alert.
    with connect_with_retry(CLIENT_ENTRY_PORT) as server_closed:
        server_closed.settimeout(0.2)
        server_closed.sendall(REQUEST)
        response = receive_exact_response(server_closed)
        if response != RESPONSE:
            fail(f"server-close protected response mismatch: {response!r}")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                if server_closed.recv(4096) == b"":
                    break
            except socket.timeout:
                continue
        else:
            fail("server-initiated close did not reach client EOF")
    wait_for_direction_event(relay_state, 1, "s2c_eof")
    wait_for_direction_event(relay_state, 1, "c2s_eof")
    validate_alerts(relay_state["scenario_alerts"][1]["s2c"], 1,
                    "server-initiated close", "s2c")
    validate_alerts(relay_state["scenario_alerts"][1]["c2s"], 0,
                    "server-initiated close", "c2s")
    if not client_closed_without_server_fin.is_set():
        fail("client waited for server FIN after authenticated close_notify")
    validate_alert_before_eof(relay_state, 1, "s2c", "server-initiated close")
    validate_wire_image(relay_state)

    # A wrong-direction protected record after authorization must produce one
    # fatal alert; the receiving client must not answer it with another alert.
    with connect_with_retry(CLIENT_ENTRY_PORT) as reflected_connection:
        reflected_connection.settimeout(0.2)
        reflected_connection.sendall(REQUEST)
        response = receive_exact_response(reflected_connection)
        if response != RESPONSE:
            fail(f"reflection-test protected response mismatch: {response!r}")
        if not reflected.wait(2.0):
            fail("relay did not reflect a downstream record upstream")
        if not server_fatal.wait(2.0):
            fail("authorized reflection did not produce a fatal-shaped record")
        time.sleep(0.1)
    wait_for_direction_event(relay_state, 2, "s2c_eof")
    validate_alerts(relay_state["scenario_alerts"][2]["s2c"], 1,
                    "server-detected corruption", "s2c")
    validate_alerts(relay_state["scenario_alerts"][2]["c2s"], 0,
                    "server-detected corruption", "c2s")
    validate_alert_before_eof(relay_state, 2, "s2c", "server-detected corruption")

    # Mirror a client record into the authorized server-to-client stream. The
    # client must emit one fatal alert and the server must not answer it.
    with connect_with_retry(CLIENT_ENTRY_PORT) as mirrored_connection:
        mirrored_connection.settimeout(0.2)
        mirrored_connection.sendall(REQUEST)
        if not mirrored.wait(3.0):
            fail("relay did not corrupt the authorized downstream stream")
        if not client_fatal.wait(3.0):
            fail("client-detected corruption did not produce a fatal-shaped record")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                if mirrored_connection.recv(4096) == b"":
                    break
            except socket.timeout:
                continue
    wait_for_direction_event(relay_state, 3, "c2s_eof")
    validate_alerts(relay_state["scenario_alerts"][3]["c2s"], 1,
                    "client-detected corruption", "c2s")
    validate_alerts(relay_state["scenario_alerts"][3]["s2c"], 0,
                    "client-detected corruption", "s2c")
    validate_alert_before_eof(relay_state, 3, "c2s", "client-detected corruption")

    # A raw record cannot establish an authorized connection by itself.
    with connect_with_retry(REALITY_SERVER_PORT) as direct:
        direct.sendall(relay_state["c2s_application"][0])
        try:
            direct.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        time.sleep(0.2)

    # A valid record from another connection must fail the connection-bound AAD.
    with connect_with_retry(CLIENT_ENTRY_PORT) as replayed:
        replayed.settimeout(0.2)
        replayed.sendall(REQUEST)
        drain_rejected_connection(replayed, cross_replayed)

    # Stage three one-byte writes and wait for relay acknowledgement between them,
    # so each write is exactly one payload callback and cannot be split or merged
    # with the next. Withhold record two and deliver record three after the first
    # record authorizes the connection to exercise strict Reality sequencing.
    with connect_with_retry(CLIENT_ENTRY_PORT) as out_of_order:
        out_of_order.settimeout(0.2)
        out_of_order.sendall(b"0")
        if not reorder_first_forwarded.wait(2.0):
            fail("relay did not forward the reorder authorization record")
        out_of_order.sendall(b"1")
        if not reorder_second_held.wait(2.0):
            fail("relay did not hold the second reorder record")
        out_of_order.sendall(b"2")
        drain_rejected_connection(out_of_order, reordered)

    if PROFILE != "tls13":
        # TLS 1.2 has an unambiguous final protected Finished in each direction.
        # Close without application data after both epochs are forwarded. The
        # client emits no first-record close alert; Pending/Visitor closes its
        # cover branch normally.
        with connect_with_retry(CLIENT_ENTRY_PORT) as immediate:
            immediate.settimeout(0.2)
            if not immediate_handshake.wait(3.0):
                fail("relay did not observe both protected cover-handshake epochs")
            time.sleep(0.05)
            try:
                immediate.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            deadline = time.monotonic() + 3.0
            saw_eof = False
            while time.monotonic() < deadline:
                try:
                    if immediate.recv(4096) == b"":
                        saw_eof = True
                        break
                except socket.timeout:
                    pass
            if not saw_eof:
                fail("immediate client close did not receive cover-path FIN")

        wait_for_direction_event(relay_state, 6, "c2s_eof")
        wait_for_direction_event(relay_state, 6, "s2c_eof")
        validate_alerts(relay_state["scenario_alerts"][6]["c2s"], 0,
                        "immediate post-handshake close", "c2s")
        validate_alerts(relay_state["scenario_alerts"][6]["s2c"], 0,
                        "immediate post-handshake close", "s2c")
        if relay_state["immediate_application"]:
            fail("immediate post-handshake close emitted protected application data")

    time.sleep(0.8)
    relay_stop.set()
    sink_stop.set()

    expected_sink_connections = 5
    if sink_state["connections"] != expected_sink_connections:
        fail(f"protected chain opened {sink_state['connections']} times; expected {expected_sink_connections}")
    expected_payloads = [REQUEST, REQUEST, REQUEST, REQUEST, b"0"]
    if sink_state["payloads"] != expected_payloads:
        fail(f"protected sink observed unexpected payloads: {sink_state['payloads']!r}")
    expected_relay_connections = 6 if PROFILE == "tls13" else 7
    if relay_state["connections"] < expected_relay_connections:
        fail(f"relay observed {relay_state['connections']} TLS connections; expected {expected_relay_connections}")


if __name__ == "__main__":
    main()
