"""Socket reads with the pilot's existing EOF and timeout diagnostics."""
import socket
import time


def exact(sock, size, *, max_chunk=None, timeout_context=True, eof_error=None, eof_returns_none=False):
    """Read size bytes, preserving partial progress in EOF/timeout failures."""
    result = bytearray()
    while len(result) < size:
        try:
            remaining = size - len(result)
            chunk = sock.recv(min(max_chunk, remaining) if max_chunk is not None else remaining)
        except socket.timeout as error:
            if not timeout_context:
                raise
            raise TimeoutError(f"timed out after receiving {len(result)} of {size} bytes") from error
        if not chunk:
            if eof_returns_none:
                return None
            if eof_error is not None:
                raise eof_error()
            raise AssertionError(f"EOF after {len(result)} of {size} bytes")
        result.extend(chunk)
    return bytes(result)


def configure_listener(sock, address, *, timeout):
    """Configure an existing TCP socket; preserve default backlog and its owner."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen()
    sock.settimeout(timeout)


def connect_when_ready(process, address, *, deadline, failure, timeout=1, pause=0.02):
    """Return the scenario's actual TCP connection, never a disposable probe.

    Retry only ConnectionRefusedError, with the caller's existing absolute
    deadline. failure constructs the caller's early-exit exception after poll.
    UDP publication, pre-attempt deadlines and other retries stay in the test.
    """
    while True:
        if process.poll() is not None:
            raise failure()
        try:
            return socket.create_connection(address, timeout=timeout)
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(pause)
