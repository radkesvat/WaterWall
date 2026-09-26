#!/usr/bin/env python3
"""Verify concurrent TCP uploads and downloads through a namespace-local chain."""

import argparse
import hashlib
import json
import math
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor


CHUNK_SIZE = 64 * 1024
MAGIC = b"WWTCPCHN"
HEADER = struct.Struct("!8sII")
ACK = b"WWTCP-VERIFIED"


def remaining(deadline):
    timeout = deadline - time.monotonic()
    if timeout <= 0:
        raise TimeoutError("transfer deadline expired")
    return timeout


def send(sock, data, deadline):
    sock.settimeout(remaining(deadline))
    sock.sendall(data)


def receive(sock, length, deadline):
    data = bytearray()
    while len(data) < length:
        sock.settimeout(remaining(deadline))
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError(f"unexpected EOF with {length - len(data)} bytes missing")
        data.extend(chunk)
    return data


def expect_eof(sock, deadline):
    sock.settimeout(remaining(deadline))
    if sock.recv(1):
        raise RuntimeError("unexpected bytes after completed transfer")


def payload(connection, direction, offset, length):
    # The offset prevents an exchanged or repeated chunk from passing validation.
    seed = struct.pack("!BII", direction, connection, offset)
    return hashlib.shake_256(seed).digest(length)


def transfer(sock, connection, direction, length, deadline, sending):
    for offset in range(0, length, CHUNK_SIZE):
        expected = payload(connection, direction, offset, min(CHUNK_SIZE, length - offset))
        if sending:
            send(sock, expected, deadline)
        elif receive(sock, len(expected), deadline) != expected:
            raise RuntimeError(
                f"connection {connection}: direction {direction} payload mismatch at offset {offset}"
            )


def serve_connection(sock, args, deadline, barrier, seen, seen_lock):
    try:
        with sock:
            magic, connection, length = HEADER.unpack(receive(sock, HEADER.size, deadline))
            if magic != MAGIC or connection >= args.connections or length != args.bytes:
                raise RuntimeError("invalid connection header")
            with seen_lock:
                if connection in seen:
                    raise RuntimeError(f"duplicate connection index {connection}")
                seen.add(connection)
            barrier.wait(remaining(deadline))
            transfer(sock, connection, 0, args.bytes, deadline, sending=False)
            transfer(sock, connection, 1, args.bytes, deadline, sending=True)
            if receive(sock, len(ACK), deadline) != ACK:
                raise RuntimeError(f"connection {connection}: missing download verification ACK")
            sock.shutdown(socket.SHUT_WR)
            expect_eof(sock, deadline)
    except BaseException:
        barrier.abort()
        raise


def server(args, deadline):
    barrier = threading.Barrier(args.connections)
    seen = set()
    seen_lock = threading.Lock()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.address, args.port))
        listener.listen(args.connections)
        print("READY", flush=True)
        with ThreadPoolExecutor(max_workers=args.connections) as executor:
            futures = []
            try:
                for _ in range(args.connections):
                    listener.settimeout(remaining(deadline))
                    sock, _ = listener.accept()
                    futures.append(executor.submit(
                        serve_connection, sock, args, deadline, barrier, seen, seen_lock
                    ))
                for future in futures:
                    future.result()
            except BaseException:
                barrier.abort()
                raise


def connect_one(connection, args, deadline, barrier):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((args.bind, args.source_port + connection))
            sock.settimeout(remaining(deadline))
            sock.connect((args.address, args.port))
            barrier.wait(remaining(deadline))
            send(sock, HEADER.pack(MAGIC, connection, args.bytes), deadline)
            transfer(sock, connection, 0, args.bytes, deadline, sending=True)
            transfer(sock, connection, 1, args.bytes, deadline, sending=False)
            send(sock, ACK, deadline)
            expect_eof(sock, deadline)
            sock.shutdown(socket.SHUT_WR)
    except BaseException:
        barrier.abort()
        raise


def client(args, deadline):
    barrier = threading.Barrier(args.connections)
    with ThreadPoolExecutor(max_workers=args.connections) as executor:
        futures = [
            executor.submit(connect_one, index, args, deadline, barrier)
            for index in range(args.connections)
        ]
        for future in futures:
            future.result()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("server", "client"))
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--connections", type=int, default=4)
    parser.add_argument("--bytes", type=int, default=1024 * 1024)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--source-port", type=int, default=40000)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if not 1 <= args.connections <= 16:
        parser.error("--connections must be between 1 and 16")
    if not 1 <= args.bytes <= 32 * 1024 * 1024:
        parser.error("--bytes must be between 1 and 33554432")
    if not 1 <= args.port <= 65535 or not 1 <= args.source_port <= 65536 - args.connections:
        parser.error("ports must fit in 1..65535, including every client source port")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 300:
        parser.error("--timeout must be finite and between 0 and 300 seconds")
    deadline = time.monotonic() + args.timeout
    try:
        (server if args.role == "server" else client)(args, deadline)
    except (OSError, RuntimeError, threading.BrokenBarrierError) as error:
        print(f"TCP chain transfer failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "role": args.role,
        "connections": args.connections,
        "upload_bytes": args.connections * args.bytes,
        "download_bytes": args.connections * args.bytes,
        "verified": True,
    }), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
