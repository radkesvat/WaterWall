"""ClientHello record observation shared by the TLS and fragmenter peers. Caller owns the socket and
expected cuts; peek bounds and original failures stay."""
import socket
import time


def inspect_client_hello(raw, expected_cuts):
    """Peek until complete records carry one ClientHello, without assuming TCP reads."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        data = raw.recv(65536, socket.MSG_PEEK)
        if not data:
            raise AssertionError("TLS peer closed before ClientHello")
        position = 0
        handshake = bytearray()
        lengths = []
        while position + 5 <= len(data):
            kind, major, minor, hi, lo = data[position:position + 5]
            length = (hi << 8) | lo
            if kind != 22 or major != 3 or minor not in (1, 2, 3) or not 1 <= length <= 16384:
                raise AssertionError("invalid ClientHello TLS record")
            if position + 5 + length > len(data):
                break
            lengths.append(length)
            handshake.extend(data[position + 5:position + 5 + length])
            position += 5 + length
            if len(handshake) >= 4:
                total = 4 + int.from_bytes(handshake[1:4], "big")
                if handshake[0] != 1 or total > 65536:
                    raise AssertionError("invalid ClientHello handshake header")
                if len(handshake) >= total:
                    if len(handshake) != total or lengths[:len(expected_cuts)] != expected_cuts:
                        raise AssertionError(f"ClientHello record cuts: {lengths}")
                    return bytes(handshake)
        time.sleep(.002)
    raise AssertionError("timed out inspecting complete ClientHello records")
