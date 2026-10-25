"""Small adapters for the checksum-pinned VMess reference executables.

V2Ray 5.53.0 and Xray 25.6.8 use their native v4 JSON schema. sing-box
1.12.0 uses its native schema. This module only translates fixture configuration;
no peer selection, downloads, retries, or feature downgrade happens at runtime.
"""

import json
import os
import socket
import subprocess

VERSIONS = {"v2ray": "5.53.0", "xray": "25.6.8", "sing-box": "1.12.0"}


class UdpSizeLimit(Exception):
    """A size probe observed a dropped or prefix-truncated datagram."""


def receive_udp_size_probe(sock, expected, phase):
    try:
        received, origin = sock.recvfrom(65535)
    except socket.timeout as error:
        raise UdpSizeLimit(f"{phase}: no complete {len(expected)}-byte datagram") from error
    if len(received) < len(expected) and expected.startswith(received):
        raise UdpSizeLimit(f"{phase}: {len(expected)} bytes truncated to {len(received)}")
    assert received == expected, f"{phase}: datagram contents changed"
    return origin


def check_udp_size_probe(args, exchange, waterwall, reference=None):
    assert args.protocol == "udp" and args.udp_size_probe in ("supported", "limited")
    if args.udp_size_probe == "limited":
        assert getattr(args, "peer", "reference") == "reference"
        assert args.reference_kind in ("v2ray", "xray") and args.cipher == "aes-128-gcm"
    # Verify readiness and complete small-packet delivery before characterizing
    # the pinned peer's limit. Startup failures are never accepted as a limit.
    exchange(bytes(range(256)) * 4)
    observed = None
    try:
        exchange(bytes(range(256)) * 32)
    except UdpSizeLimit as error:
        if args.udp_size_probe != "limited":
            raise
        observed = error
    waterwall.check_running("UDP size probe")
    if reference is not None:
        reference.check_running("UDP size probe")
    if args.udp_size_probe == "limited":
        assert observed is not None, "pinned peer now preserves 8192-byte UDP; update its documented limit"
        print(f"Confirmed pinned {args.reference_kind} UDP size limitation: {observed}; "
              "this is not successful 8 KiB interoperability", flush=True)
    else:
        print("Verified intact 8192-byte UDP request and reply", flush=True)


def validate_reference(executable, kind):
    if not executable.is_file():
        raise RuntimeError(f"pinned {kind} missing; build waterwall_vmess_reference first")
    result = subprocess.run([str(executable), "version"], check=True, capture_output=True,
                            text=True, timeout=5).stdout
    prefix = {"v2ray": "V2Ray", "xray": "Xray", "sing-box": "sing-box version"}[kind]
    assert result.splitlines()[0].split()[:len(prefix.split()) + 1] == [*prefix.split(), VERSIONS[kind]], f"unexpected {kind} version: {result.splitlines()[0]}"


def write_reference(root, kind, config, *, server, packet_encoding="none", no_termination=False):
    if kind == "xray" and not server:
        for user in config["outbounds"][0]["settings"]["vnext"][0]["users"]:
            user["experiments"] = "NoTerminationSignal" if no_termination else ""
    if kind == "v2ray" and packet_encoding == "packetaddr" and not server:
        config["inbounds"][0]["settings"]["packetEncoding"] = "Packet"
    if kind == "xray" and packet_encoding != "none":
        raise ValueError("Xray 25.6.8 has XUDP, not the packetaddr envelope tested here")
    if kind == "sing-box":
        inbound = config["inbounds"][0]
        outbound = config["outbounds"][0]
        stream = inbound.get("streamSettings", {}) if server else outbound["streamSettings"]
        if server:
            vmess = {"type": "vmess", "listen": inbound["listen"], "listen_port": inbound["port"],
                     "users": [{"name": "fixture", "uuid": inbound["settings"]["clients"][0]["id"],
                                "alterId": 0}]}
            converted = {"inbounds": [vmess], "outbounds": [{"type": "direct"}]}
        else:
            endpoint = outbound["settings"]["vnext"][0]
            user = endpoint["users"][0]
            vmess = {"type": "vmess", "server": endpoint["address"], "server_port": endpoint["port"],
                     "uuid": user["id"], "security": user["security"], "alter_id": 0,
                     "packet_encoding": packet_encoding if packet_encoding != "none" else ""}
            converted = {"inbounds": [{"type": "socks", "listen": inbound["listen"],
                                       "listen_port": inbound["port"]}], "outbounds": [vmess]}
        if stream.get("network") == "ws":
            vmess["transport"] = {"type": "ws", "path": stream["wsSettings"]["path"]}
            if not server:
                vmess["transport"]["headers"] = stream["wsSettings"].get("headers", {})
        if stream.get("security") == "tls":
            tls = stream["tlsSettings"]
            vmess["tls"] = {"enabled": True}
            if server:
                certificate = tls["certificates"][0]
                vmess["tls"].update({"certificate_path": certificate["certificateFile"],
                                     "key_path": certificate["keyFile"]})
            else:
                vmess["tls"].update({"server_name": tls["serverName"], "insecure": tls["allowInsecure"]})
                if not tls["allowInsecure"]:
                    vmess["tls"]["certificate_path"] = tls["certificates"][0]["certificateFile"]
        config = {"log": {"level": "debug"}, **converted}
    (root / "reference.json").write_text(json.dumps(config))


def command(executable, root):
    return [str(executable), "run", "-c", str(root / "reference.json")]


def environment(kind):
    result = os.environ.copy()
    if kind == "xray":
        # v25.6.8 core/xray.go reads this public EnvFlag. Its default cone
        # behavior converts native UDP to excluded XUDP/Mux command3; these
        # fixtures deliberately select ordinary fixed-destination VMess UDP.
        result["xray.cone.disabled"] = "true"
        result["XRAY_CONE_DISABLED"] = "true"
    return result


def packetaddr_payload_size(args):
    if args.packetaddr_payload_profile == "protocol-limit" or getattr(args, "peer", "reference") == "waterwall":
        return 65400
    if args.reference_kind == "v2ray":
        # v5.53.0 common/crypto/auth.go caps the complete packet frame at 2048.
        return 1940
    # sing-box 1.12.0 pins sing-vmess 0.2.6: protocol.go WriteChunkSize=15000.
    # Its encrypted writer splits larger plaintext, including the envelope.
    return 15000 - (7 if args.target == "ipv4" else 19)


def unsupported_packetaddr_profile(args):
    if (args.protocol == "udp" and args.packet_encoding == "packetaddr" and
            args.packetaddr_payload_profile == "protocol-limit" and args.reference_kind == "sing-box" and
            getattr(args, "peer", "reference") == "reference"):
        print("Unsupported frozen peer cell: sing-box 1.12.0 packetaddr payload 65400; "
              "pinned sing-vmess 0.2.6 splits encrypted plaintext at 15000 and reads chunks into 16384 bytes. "
              "See sing-vmess v0.2.6 protocol.go ReadChunkSize/WriteChunkSize. "
              "This cell is skipped, not passed.", flush=True)
        return True
    return False
