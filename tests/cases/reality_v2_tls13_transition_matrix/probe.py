from collections import Counter
import socket
import ssl
import sys
import threading
import time


HOST = "127.0.0.1"
CLIENT_ENTRY_PORT = 25130
MAIN_RELAY_PORT = 25131
REALITY_SERVER_PORT = 25132
COVER_RELAY_PORT = 25133
TLS_SERVER_PORT = 25134
PROTECTED_SINK_PORT = 25135

REQUEST = b"transition-matrix-request"
RESPONSE = b"transition-matrix-response"
COVER_APPLICATION = b"cover-application-before-ack"
TLS_APPLICATION_HEADER = b"\x17\x03\x03"
CONTROL_MIN_BODY_LENGTH = 22
CONTROL_MAX_BODY_LENGTH = 1172

SCENARIOS = (
    {"name": "no-ticket", "tickets": 0, "expect_success": True},
    {
        "name": "cross-connection-replayed-request",
        "tickets": 0,
        "main_mode": "replay_previous_request",
        "expect_success": False,
    },
    {"name": "one-ticket-immediate", "tickets": 1, "expect_success": True},
    {"name": "multiple-tickets-immediate", "tickets": 2, "expect_success": True},
    {
        "name": "ticket-delayed-past-request-cutoff",
        "tickets": 1,
        "cover_mode": "delay_until_request",
        "expect_success": True,
    },
    {
        "name": "ticket-byte-split",
        "tickets": 1,
        "cover_mode": "byte_split",
        "expect_success": True,
    },
    {
        "name": "ticket-ack-coalesced",
        "tickets": 1,
        "main_mode": "coalesce_ticket_ack",
        "expect_success": True,
    },
    {
        "name": "cover-application-before-ack",
        "tickets": 0,
        "cover_action": "application",
        "expect_success": True,
    },
    {
        "name": "partial-ticket-at-request-boundary",
        "tickets": 1,
        "cover_mode": "partial_until_request",
        "main_mode": "coordinate_partial_request",
        "expect_success": True,
    },
    {
        "name": "segmented-controls-and-cover",
        "tickets": 1,
        "cover_mode": "record_segmented",
        "main_mode": "record_segmented",
        "expect_success": True,
    },
    {
        "name": "cover-close-notify-before-ack",
        "tickets": 0,
        "cover_action": "close_notify",
        "expect_success": False,
    },
    {
        "name": "corrupted-request",
        "tickets": 1,
        "main_mode": "corrupt_request",
        "expect_success": False,
    },
    {
        "name": "corrupted-ack",
        "tickets": 1,
        "main_mode": "corrupt_ack",
        "expect_success": False,
    },
    {
        "name": "corrupted-confirm",
        "tickets": 1,
        "main_mode": "corrupt_confirm",
        "expect_success": False,
    },
)


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
    if body_length > 18432:
        raise OSError(f"oversized TLS record body: {body_length}")
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


def receive_response(sock, timeout=5.0):
    result = b""
    deadline = time.monotonic() + timeout
    while len(result) < len(RESPONSE) and time.monotonic() < deadline:
        try:
            chunk = sock.recv(len(RESPONSE) - len(result))
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        result += chunk
    return result


def expected_main_cover_record_count(scenario):
    if scenario.get("cover_mode") == "delay_until_request":
        return 0
    count = scenario["tickets"]
    if scenario.get("cover_action") in ("application", "close_notify"):
        count += 1
    return count


def immediate_cover_record_count(scenario):
    if scenario.get("cover_mode") == "partial_until_request":
        return 0
    return expected_main_cover_record_count(scenario)


def new_runtime(scenario):
    return {
        "scenario": scenario,
        "request_forwarded": threading.Event(),
        "partial_prefix_sent": threading.Event(),
        "cover_client_finished": threading.Event(),
        "main_client_finished": threading.Event(),
        "main_cover_ready": threading.Event(),
        "cover_source_ready": threading.Event(),
        "ack_forwarded": threading.Event(),
        "confirm_forwarded": threading.Event(),
        "main_done": threading.Event(),
        "cover_done": threading.Event(),
        "tls_done": threading.Event(),
        "main": {"c2s": [], "s2c": [], "events": [], "roles": [], "writes": []},
        "cover": {"c2s": [], "s2c": [], "events": [], "writes": []},
        "evidence": {},
        "errors": [],
        "lock": threading.Lock(),
    }


RUNTIMES = [new_runtime(scenario) for scenario in SCENARIOS]


def record_event(runtime, relay_name, direction, record):
    now = time.monotonic()
    with runtime["lock"]:
        records = runtime[relay_name][direction]
        index = len(records)
        records.append(record)
        runtime[relay_name]["events"].append((direction, index, now))
    return index


def record_write(runtime, relay_name, direction, record_indices, chunks):
    with runtime["lock"]:
        runtime[relay_name]["writes"].append(
            {
                "direction": direction,
                "records": tuple(record_indices),
                "chunks": tuple(chunks),
                "time": time.monotonic(),
            }
        )


def record_role(runtime, direction, record_index, role):
    with runtime["lock"]:
        runtime["main"]["roles"].append((direction, record_index, role))


def send_chunks(destination, data, chunk_sizes, delay=0.0):
    offset = 0
    actual = []
    for requested in chunk_sizes:
        if offset >= len(data):
            break
        length = min(requested, len(data) - offset)
        destination.sendall(data[offset : offset + length])
        actual.append(length)
        offset += length
        if delay:
            time.sleep(delay)
    if offset < len(data):
        destination.sendall(data[offset:])
        actual.append(len(data) - offset)
    return actual


def send_segmented(destination, record):
    return send_chunks(destination, record, (1, 2, 1, 3, 5, 8, 13), delay=0.001)


def start_indexed_listener(port, name, handler):
    state = {"ready": False, "errors": [], "accepted": 0}
    stop = threading.Event()

    def run():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((HOST, port))
                listener.listen(len(SCENARIOS))
                listener.settimeout(0.2)
                state["ready"] = True
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    index = state["accepted"]
                    state["accepted"] += 1
                    if index >= len(RUNTIMES):
                        conn.close()
                        state["errors"].append(f"{name}: unexpected extra connection")
                        continue
                    threading.Thread(
                        target=handler,
                        args=(conn, RUNTIMES[index]),
                        daemon=True,
                    ).start()
        except OSError as error:
            state["errors"].append(f"{name}: {error}")
            state["ready"] = True

    threading.Thread(target=run, daemon=True).start()
    return state, stop


def start_tls_cover_server():
    state = {"handshakes": 0, "unexpected_plaintext": [], "errors": []}
    state_lock = threading.Lock()

    def handle(conn, runtime):
        scenario = runtime["scenario"]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain("server.crt", "server.key")
        context.num_tickets = scenario["tickets"]
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                with state_lock:
                    state["handshakes"] += 1
                action = scenario.get("cover_action")
                if action == "application":
                    tls.sendall(COVER_APPLICATION)
                elif action == "close_notify":
                    tls.settimeout(0.25)
                    try:
                        tls.unwrap()
                    except (ssl.SSLError, OSError, socket.timeout):
                        pass
                    return

                tls.settimeout(0.2)
                deadline = time.monotonic() + 6.0
                while time.monotonic() < deadline:
                    try:
                        data = tls.recv(4096)
                    except socket.timeout:
                        continue
                    except (ssl.SSLError, OSError):
                        break
                    if not data:
                        break
                    with state_lock:
                        state["unexpected_plaintext"].append(
                            (scenario["name"], data)
                        )
        except (ssl.SSLError, OSError) as error:
            if scenario["expect_success"]:
                runtime["errors"].append(f"TLS cover: {error}")
            conn.close()
        finally:
            runtime["tls_done"].set()

    listener_state, stop = start_indexed_listener(TLS_SERVER_PORT, "TLS cover", handle)
    state["listener"] = listener_state
    return state, stop


def start_cover_relay():
    def handle(client, runtime):
        scenario = runtime["scenario"]
        try:
            server = socket.create_connection((HOST, TLS_SERVER_PORT), timeout=2.0)
        except OSError as error:
            runtime["errors"].append(f"cover relay connect: {error}")
            client.close()
            runtime["cover_done"].set()
            return
        client.settimeout(6.0)
        server.settimeout(6.0)
        c2s_ccs = False
        post_handshake_count = 0

        def upstream():
            nonlocal c2s_ccs
            try:
                while True:
                    record = recv_tls_record(client)
                    if record is None:
                        break
                    index = record_event(runtime, "cover", "c2s", record)
                    if record[0] == 0x14:
                        c2s_ccs = True
                    elif c2s_ccs and record[:3] == TLS_APPLICATION_HEADER:
                        runtime["cover_client_finished"].set()
                    server.sendall(record)
                    record_write(runtime, "cover", "c2s", (index,), (len(record),))
            except (OSError, socket.timeout) as error:
                if scenario["expect_success"] and not runtime["confirm_forwarded"].is_set():
                    runtime["errors"].append(f"cover c2s pump: {error}")
            finally:
                try:
                    server.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        def downstream():
            nonlocal post_handshake_count
            try:
                while True:
                    record = recv_tls_record(server)
                    if record is None:
                        break
                    index = record_event(runtime, "cover", "s2c", record)
                    is_post_handshake = (
                        runtime["cover_client_finished"].is_set()
                        and not runtime["confirm_forwarded"].is_set()
                        and record[:3] == TLS_APPLICATION_HEADER
                    )
                    if is_post_handshake:
                        post_handshake_count += 1
                        runtime["evidence"]["cover_post_handshake_records"] = (
                            post_handshake_count
                        )
                        runtime["cover_source_ready"].set()

                    mode = scenario.get("cover_mode")
                    if is_post_handshake and post_handshake_count == 1 and mode == "delay_until_request":
                        if not runtime["request_forwarded"].wait(2.0):
                            raise OSError("request was not observed before delayed ticket")
                        time.sleep(0.03)
                        runtime["evidence"]["ticket_released_after_request"] = True
                        client.sendall(record)
                        chunks = (len(record),)
                    elif is_post_handshake and post_handshake_count == 1 and mode == "partial_until_request":
                        prefix_len = min(8, len(record) - 1)
                        client.sendall(record[:prefix_len])
                        runtime["partial_prefix_sent"].set()
                        if not runtime["request_forwarded"].wait(2.0):
                            raise OSError("request was not forwarded at the partial ticket boundary")
                        time.sleep(0.03)
                        client.sendall(record[prefix_len:])
                        chunks = (prefix_len, len(record) - prefix_len)
                        runtime["evidence"]["partial_ticket_prefix"] = prefix_len
                    elif is_post_handshake and mode == "byte_split":
                        chunks = tuple(send_chunks(client, record, (1,) * len(record), delay=0.0002))
                        runtime["evidence"]["byte_split_ticket_chunks"] = len(chunks)
                    elif mode == "record_segmented":
                        chunks = tuple(send_segmented(client, record))
                    else:
                        client.sendall(record)
                        chunks = (len(record),)
                    record_write(runtime, "cover", "s2c", (index,), chunks)
            except (OSError, socket.timeout) as error:
                cutoff_write_is_expected = (
                    scenario.get("cover_mode") == "delay_until_request"
                    and runtime["request_forwarded"].is_set()
                )
                if (
                    scenario["expect_success"]
                    and not runtime["confirm_forwarded"].is_set()
                    and not cutoff_write_is_expected
                ):
                    runtime["errors"].append(f"cover s2c pump: {error}")
            finally:
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        up = threading.Thread(target=upstream, daemon=True)
        down = threading.Thread(target=downstream, daemon=True)
        up.start()
        down.start()
        up.join(7.0)
        down.join(7.0)
        client.close()
        server.close()
        runtime["cover_done"].set()

    return start_indexed_listener(COVER_RELAY_PORT, "cover relay", handle)


def start_main_relay():
    replay_state = {"request": None, "scenario": None}
    replay_lock = threading.Lock()

    def handle(client, runtime):
        scenario = runtime["scenario"]
        mode = scenario.get("main_mode")
        try:
            server = socket.create_connection((HOST, REALITY_SERVER_PORT), timeout=2.0)
        except OSError as error:
            runtime["errors"].append(f"main relay connect: {error}")
            client.close()
            runtime["main_done"].set()
            return
        client.settimeout(6.0)
        server.settimeout(6.0)

        def upstream():
            ccs_seen = False
            client_finished_seen = False
            request_seen = False
            confirm_seen = False
            application_seen = False
            try:
                while True:
                    record = recv_tls_record(client)
                    if record is None:
                        break
                    index = record_event(runtime, "main", "c2s", record)
                    role = None
                    if record[0] == 0x14:
                        ccs_seen = True
                    elif ccs_seen and record[:3] == TLS_APPLICATION_HEADER:
                        if not client_finished_seen:
                            role = "client_finished"
                            client_finished_seen = True
                            runtime["main_client_finished"].set()
                        elif not request_seen:
                            role = "request"
                            request_seen = True
                        elif runtime["ack_forwarded"].is_set() and not confirm_seen:
                            role = "confirm"
                            confirm_seen = True
                        elif confirm_seen and not application_seen:
                            role = "client_application"
                            application_seen = True
                        elif confirm_seen:
                            role = "client_post_application"
                        else:
                            role = "unexpected_pre_ack_client_record"
                    if role is not None:
                        record_role(runtime, "c2s", index, role)

                    forwarded = record
                    if mode == "replay_previous_request" and role == "request":
                        with replay_lock:
                            replay = replay_state["request"]
                            replay_scenario = replay_state["scenario"]
                        if replay is None:
                            raise OSError("no previous REQUEST was captured for replay")
                        if replay == record:
                            raise OSError("fresh and replay-source REQUEST records unexpectedly match")
                        forwarded = replay
                        runtime["evidence"]["replayed_request"] = True
                        runtime["evidence"]["replay_source_scenario"] = replay_scenario
                        runtime["evidence"]["replay_body_lengths"] = (
                            int.from_bytes(replay[3:5], "big"),
                            int.from_bytes(record[3:5], "big"),
                        )
                    elif mode == "corrupt_request" and role == "request":
                        forwarded = record[:-1] + bytes((record[-1] ^ 0x80,))
                        runtime["evidence"]["corrupted_request"] = True
                    elif mode == "corrupt_confirm" and role == "confirm":
                        forwarded = record[:-1] + bytes((record[-1] ^ 0x40,))
                        runtime["evidence"]["corrupted_confirm"] = True

                    if mode == "coordinate_partial_request" and role == "request":
                        if not runtime["partial_prefix_sent"].wait(2.0):
                            raise OSError("partial ticket prefix was not emitted before REQUEST")
                    if (
                        role == "request"
                        and scenario.get("cover_mode") == "delay_until_request"
                        and not runtime["cover_source_ready"].wait(2.0)
                    ):
                        raise OSError("delayed ticket was not captured before REQUEST")
                    if role == "request":
                        expected_cover = immediate_cover_record_count(scenario)
                        if expected_cover and not runtime["main_cover_ready"].wait(2.0):
                            raise OSError(
                                f"only {runtime['evidence'].get('main_cover_records', 0)} of "
                                f"{expected_cover} immediate cover records arrived before REQUEST"
                            )

                    if mode == "record_segmented" and role in ("request", "confirm"):
                        chunks = tuple(send_segmented(server, forwarded))
                    else:
                        server.sendall(forwarded)
                        chunks = (len(forwarded),)
                    record_write(runtime, "main", "c2s", (index,), chunks)
                    if role == "request":
                        if scenario["expect_success"]:
                            with replay_lock:
                                replay_state["request"] = record
                                replay_state["scenario"] = scenario["name"]
                        runtime["request_forwarded"].set()
                    elif role == "confirm":
                        runtime["confirm_forwarded"].set()
            except (OSError, socket.timeout) as error:
                if scenario["expect_success"] and not runtime["confirm_forwarded"].is_set():
                    runtime["errors"].append(f"main c2s pump: {error}")
            finally:
                try:
                    server.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        def downstream():
            ccs_seen = False
            ack_seen = False
            application_seen = False
            held = None
            try:
                while True:
                    record = recv_tls_record(server)
                    if record is None:
                        break
                    index = record_event(runtime, "main", "s2c", record)
                    role = None
                    if record[0] == 0x14:
                        ccs_seen = True
                    elif ccs_seen and record[:3] == TLS_APPLICATION_HEADER:
                        if not runtime["main_client_finished"].is_set():
                            role = "server_handshake"
                        elif runtime["evidence"].get(
                            "main_cover_records", 0
                        ) < expected_main_cover_record_count(scenario):
                            role = "cover"
                            count = runtime["evidence"].get("main_cover_records", 0) + 1
                            runtime["evidence"]["main_cover_records"] = count
                            if count >= immediate_cover_record_count(scenario):
                                runtime["main_cover_ready"].set()
                        elif not ack_seen:
                            role = "ack"
                            ack_seen = True
                        elif not application_seen:
                            role = "server_application"
                            application_seen = True
                        else:
                            role = "server_post_application"
                    if role is not None:
                        record_role(runtime, "s2c", index, role)

                    if mode == "coalesce_ticket_ack" and role == "cover":
                        held = (index, record)
                        continue
                    if mode == "coalesce_ticket_ack" and role == "ack" and held is not None:
                        client.sendall(held[1] + record)
                        record_write(
                            runtime,
                            "main",
                            "s2c",
                            (held[0], index),
                            (len(held[1]) + len(record),),
                        )
                        runtime["evidence"]["ticket_ack_coalesced"] = True
                        held = None
                        runtime["ack_forwarded"].set()
                        continue

                    forwarded = record
                    if mode == "corrupt_ack" and role == "ack":
                        forwarded = record[:-1] + bytes((record[-1] ^ 0x20,))
                        runtime["evidence"]["corrupted_ack"] = True

                    if mode == "record_segmented" and role in ("cover", "ack"):
                        chunks = tuple(send_segmented(client, forwarded))
                    else:
                        client.sendall(forwarded)
                        chunks = (len(forwarded),)
                    record_write(runtime, "main", "s2c", (index,), chunks)
                    if role == "ack":
                        runtime["ack_forwarded"].set()
            except (OSError, socket.timeout) as error:
                if scenario["expect_success"] and not runtime["confirm_forwarded"].is_set():
                    runtime["errors"].append(f"main s2c pump: {error}")
            finally:
                if held is not None:
                    try:
                        client.sendall(held[1])
                    except OSError:
                        pass
                try:
                    client.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        up = threading.Thread(target=upstream, daemon=True)
        down = threading.Thread(target=downstream, daemon=True)
        up.start()
        down.start()
        up.join(7.0)
        down.join(7.0)
        client.close()
        server.close()
        runtime["main_done"].set()

    return start_indexed_listener(MAIN_RELAY_PORT, "main relay", handle)


def start_protected_sink():
    state = {"ready": False, "connections": 0, "requests": [], "errors": []}
    stop = threading.Event()

    def handle(conn):
        try:
            conn.settimeout(4.0)
            request = recv_exact(conn, len(REQUEST))
            state["requests"].append(request)
            if request == REQUEST:
                conn.sendall(RESPONSE)
        except (OSError, socket.timeout) as error:
            state["errors"].append(str(error))
        finally:
            conn.close()

    def run():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((HOST, PROTECTED_SINK_PORT))
                listener.listen(len(SCENARIOS))
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
    return state, stop


def wait_ready(states):
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if all(state["ready"] for state in states):
            return
        time.sleep(0.01)
    fail("transition-matrix fixtures did not start")


def protected_records(records, direction):
    ccs_index = next(
        (index for index, record in enumerate(records) if record[0] == 0x14),
        None,
    )
    if ccs_index is None:
        fail(f"{direction} did not emit a compatibility ChangeCipherSpec")
    protected = records[ccs_index + 1 :]
    for record in protected:
        if record[:3] != TLS_APPLICATION_HEADER:
            fail(f"{direction} emitted a non-TLS-1.3 protected header: {record[:5].hex()}")
        if len(record) != int.from_bytes(record[3:5], "big") + 5:
            fail(f"{direction} emitted a truncated TLS record")
    return protected, ccs_index + 1


def event_position(events, direction, record_index):
    for position, event in enumerate(events):
        if event[0] == direction and event[1] == record_index:
            return position, event[2]
    fail(f"missing {direction} record {record_index} from relay events")


def exact_role_record(capture, role):
    matches = [entry for entry in capture["roles"] if entry[2] == role]
    if len(matches) != 1:
        fail(f"expected exactly one {role} record, observed {matches}")
    direction, record_index, _ = matches[0]
    return capture[direction][record_index], direction, record_index


def validate_success(runtime, sink_before):
    scenario = runtime["scenario"]
    with runtime["lock"]:
        capture = {
            "c2s": list(runtime["main"]["c2s"]),
            "s2c": list(runtime["main"]["s2c"]),
            "events": list(runtime["main"]["events"]),
            "roles": list(runtime["main"]["roles"]),
            "writes": list(runtime["main"]["writes"]),
        }
        cover_s2c = list(runtime["cover"]["s2c"])

    c2s_protected, c2s_offset = protected_records(capture["c2s"], "client")
    s2c_protected, s2c_offset = protected_records(capture["s2c"], "server")
    if len(c2s_protected) < 4 or len(s2c_protected) < 3:
        fail(
            f"{scenario['name']}: incomplete handoff capture: "
            f"c2s={len(c2s_protected)}, s2c={len(s2c_protected)}"
        )

    request_record, _, request_index = exact_role_record(capture, "request")
    ack_record, _, ack_index = exact_role_record(capture, "ack")
    confirm_record, _, confirm_index = exact_role_record(capture, "confirm")
    client_application, _, application_index = exact_role_record(
        capture, "client_application"
    )
    server_application, _, _ = exact_role_record(capture, "server_application")
    controls = (request_record, ack_record, confirm_record)

    for name, record in zip(("REQUEST", "ACK", "CONFIRM"), controls):
        body_length = int.from_bytes(record[3:5], "big")
        if not CONTROL_MIN_BODY_LENGTH <= body_length <= CONTROL_MAX_BODY_LENGTH:
            fail(f"{scenario['name']}: {name} body {body_length} is outside control policy")

    if int.from_bytes(client_application[3:5], "big") != len(REQUEST) + 17:
        fail(f"{scenario['name']}: client application was not last after CONFIRM")
    if int.from_bytes(server_application[3:5], "big") != len(RESPONSE) + 17:
        fail(f"{scenario['name']}: server application was not last after ACK")

    request_pos, request_time = event_position(capture["events"], "c2s", request_index)
    ack_pos, ack_time = event_position(capture["events"], "s2c", ack_index)
    confirm_pos, confirm_time = event_position(capture["events"], "c2s", confirm_index)
    application_pos, application_time = event_position(
        capture["events"], "c2s", application_index
    )
    if not request_pos < ack_pos < confirm_pos < application_pos:
        fail(
            f"{scenario['name']}: control/application ordering was "
            f"REQUEST={request_pos}, ACK={ack_pos}, CONFIRM={confirm_pos}, APP={application_pos}"
        )

    cover_entries = [entry for entry in capture["roles"] if entry[2] == "cover"]
    cover_positions = [
        event_position(capture["events"], direction, record_index)[0]
        for direction, record_index, _ in cover_entries
    ]
    if any(position >= ack_pos for position in cover_positions):
        fail(f"{scenario['name']}: a destination cover record appeared at or after ACK")
    if scenario.get("cover_mode") == "partial_until_request":
        if not cover_positions or not all(request_pos < position for position in cover_positions):
            fail(f"{scenario['name']}: final partial cover record did not complete after REQUEST")
    post_handshake_cover_count = len(cover_entries)
    cover_source_count = runtime["evidence"].get("cover_post_handshake_records", 0)
    expected_source_count = scenario["tickets"]
    if scenario.get("cover_action") == "application":
        expected_source_count += 1
    if cover_source_count != expected_source_count:
        fail(
            f"{scenario['name']}: cover endpoint emitted {cover_source_count} protected "
            f"post-handshake records, expected {expected_source_count}"
        )
    if scenario.get("cover_mode") == "delay_until_request":
        if post_handshake_cover_count != 0:
            fail(f"{scenario['name']}: destination bytes escaped after ACK cutoff")
        if not runtime["evidence"].get("ticket_released_after_request"):
            fail(f"{scenario['name']}: delayed ticket was not actually released")
    else:
        expected_cover = scenario["tickets"]
        if scenario.get("cover_action") == "application":
            expected_cover += 1
        if post_handshake_cover_count != expected_cover:
            fail(
                f"{scenario['name']}: observed {post_handshake_cover_count} post-handshake cover "
                f"records before ACK, expected {expected_cover}"
            )

    if scenario.get("cover_mode") == "byte_split" and not runtime["evidence"].get(
        "byte_split_ticket_chunks"
    ):
        fail(f"{scenario['name']}: ticket was not byte-split")
    if scenario.get("cover_mode") == "partial_until_request" and not runtime["evidence"].get(
        "partial_ticket_prefix"
    ):
        fail(f"{scenario['name']}: partial destination boundary was not exercised")
    if scenario.get("main_mode") == "coalesce_ticket_ack" and not runtime["evidence"].get(
        "ticket_ack_coalesced"
    ):
        fail(f"{scenario['name']}: ticket and ACK were not written in one TCP send")
    if scenario.get("main_mode") == "record_segmented":
        segmented_writes = [write for write in capture["writes"] if len(write["chunks"]) > 1]
        if len(segmented_writes) < 3:
            fail(f"{scenario['name']}: controls were not observably segmented")

    wire = b"".join(capture["c2s"] + capture["s2c"])
    for marker in (b"HANDOFF_REQUEST", b"HANDOFF_ACK", b"HANDOFF_CONFIRM", REQUEST, RESPONSE):
        if marker in wire:
            fail(f"{scenario['name']}: plaintext marker escaped on the public wire")

    timing = {
        "request_to_ack_ms": round((ack_time - request_time) * 1000, 3),
        "ack_to_confirm_ms": round((confirm_time - ack_time) * 1000, 3),
        "confirm_to_app_ms": round((application_time - confirm_time) * 1000, 3),
    }
    cover_bodies = [
        int.from_bytes(capture[direction][record_index][3:5], "big")
        for direction, record_index, _ in cover_entries
    ]
    print(
        f"scenario={scenario['name']} cover_bodies={cover_bodies} "
        f"controls={[int.from_bytes(record[3:5], 'big') for record in controls]} "
        f"timing={timing} cover_source_records={len(cover_s2c)} evidence={runtime['evidence']}"
    )
    return [int.from_bytes(record[3:5], "big") for record in controls]


def validate_failure(runtime, sink_before, sink_state):
    scenario = runtime["scenario"]
    if sink_state["connections"] != sink_before:
        fail(f"{scenario['name']}: protected chain opened before authenticated handoff")
    mode = scenario.get("main_mode")
    if mode == "corrupt_request" and not runtime["evidence"].get("corrupted_request"):
        fail("corrupted-request scenario did not mutate REQUEST")
    if mode == "replay_previous_request" and not runtime["evidence"].get(
        "replayed_request"
    ):
        fail("cross-connection replay scenario did not substitute the prior REQUEST")
    if mode == "corrupt_ack" and not runtime["evidence"].get("corrupted_ack"):
        fail("corrupted-ack scenario did not mutate ACK")
    if mode == "corrupt_confirm" and not runtime["evidence"].get("corrupted_confirm"):
        fail("corrupted-confirm scenario did not mutate CONFIRM")
    if scenario.get("cover_action") == "close_notify":
        source_records = runtime["evidence"].get("cover_post_handshake_records", 0)
        relayed_records = runtime["evidence"].get("main_cover_records", 0)
        if source_records != 1 or relayed_records != 1:
            fail(
                "cover-close-notify scenario did not observe exactly one protected "
                f"source/relayed record: source={source_records}, relayed={relayed_records}"
            )
    print(
        f"scenario={scenario['name']} closed_pre_authorization=true "
        f"main_records={{c2s:{len(runtime['main']['c2s'])},s2c:{len(runtime['main']['s2c'])}}} "
        f"evidence={runtime['evidence']}"
    )


def main():
    tls_state, tls_stop = start_tls_cover_server()
    cover_state, cover_stop = start_cover_relay()
    main_state, main_stop = start_main_relay()
    sink_state, sink_stop = start_protected_sink()
    wait_ready((tls_state["listener"], cover_state, main_state, sink_state))

    control_lengths = []
    successful = 0
    failed_as_expected = 0
    try:
        for runtime in RUNTIMES:
            scenario = runtime["scenario"]
            sink_before = sink_state["connections"]
            with connect_with_retry(CLIENT_ENTRY_PORT) as client:
                client.settimeout(0.1)
                client.sendall(REQUEST)
                response = receive_response(
                    client,
                    timeout=5.0 if scenario["expect_success"] else 1.5,
                )
                if scenario["expect_success"] and response != RESPONSE:
                    fail(f"{scenario['name']}: protected response mismatch: {response!r}")
                if not scenario["expect_success"] and response == RESPONSE:
                    fail(f"{scenario['name']}: corrupted/pre-close handoff reached protected sink")

            if not runtime["main_done"].wait(4.0):
                fail(f"{scenario['name']}: public relay did not reach terminal state")
            time.sleep(0.03)
            if runtime["errors"]:
                fail(f"{scenario['name']}: fixture errors: {runtime['errors']}")

            if scenario["expect_success"]:
                deadline = time.monotonic() + 1.0
                while sink_state["connections"] < sink_before + 1 and time.monotonic() < deadline:
                    time.sleep(0.01)
                if sink_state["connections"] != sink_before + 1:
                    fail(f"{scenario['name']}: protected sink did not open exactly once")
                control_lengths.extend(validate_success(runtime, sink_before))
                successful += 1
            else:
                stable_deadline = time.monotonic() + 0.35
                while time.monotonic() < stable_deadline:
                    if sink_state["connections"] != sink_before:
                        fail(
                            f"{scenario['name']}: protected chain opened after the "
                            "expected pre-authorization close"
                        )
                    time.sleep(0.01)
                validate_failure(runtime, sink_before, sink_state)
                failed_as_expected += 1

        expected_requests = [REQUEST] * successful
        if sink_state["requests"] != expected_requests:
            fail(f"protected sink requests mismatch: {sink_state['requests']!r}")
        fixture_errors = (
            tls_state["listener"]["errors"]
            + cover_state["errors"]
            + main_state["errors"]
            + sink_state["errors"]
        )
        if fixture_errors:
            fail(f"fixture listener errors: {fixture_errors}")
        if tls_state["unexpected_plaintext"]:
            fail(f"Reality bytes reached cover TLS plaintext: {tls_state['unexpected_plaintext']!r}")

        histogram = Counter(control_lengths)
        if len(histogram) < 2:
            fail(f"control public-length histogram collapsed: {dict(histogram)}")
        print(f"control_body_histogram={dict(sorted(histogram.items()))}")
        print(
            f"transition_matrix_complete successes={successful} "
            f"expected_pre_auth_closes={failed_as_expected} handshakes={tls_state['handshakes']}"
        )
    finally:
        sink_stop.set()
        main_stop.set()
        cover_stop.set()
        tls_stop.set()


if __name__ == "__main__":
    main()
