#!/usr/bin/env python3

import copy
import json
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


STARTED_MARKER = "Core: starting workers ..."


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def make_config(kind, settings):
    port = get_free_port()
    nodes = [
        {
            "name": "listener",
            "type": "TcpListener",
            "settings": {"address": "127.0.0.1", "port": port},
            "next": "target",
        }
    ]

    if kind == "client":
        nodes.extend(
            [
                {
                    "name": "target",
                    "type": "RealityClient",
                    "settings": settings,
                    "next": "protected",
                },
                {"name": "protected", "type": "BlackHole", "settings": {"mode": "passive"}},
            ]
        )
    elif kind == "server":
        nodes.extend(
            [
                {
                    "name": "target",
                    "type": "RealityServer",
                    "settings": settings,
                    "next": "protected",
                },
                {"name": "protected", "type": "BlackHole", "settings": {"mode": "passive"}},
                {"name": "visitor", "type": "BlackHole", "settings": {"mode": "passive"}},
            ]
        )
    elif kind == "tls":
        nodes.extend(
            [
                {
                    "name": "target",
                    "type": "TlsClient",
                    "settings": settings,
                    "next": "protected",
                },
                {"name": "protected", "type": "BlackHole", "settings": {"mode": "passive"}},
            ]
        )
    else:
        raise AssertionError(f"unknown configuration kind: {kind}")

    return {"name": f"reality-configuration-{kind}", "nodes": nodes}


def core_config():
    return {
        "log": {
            "path": "log/",
            "internal": {"loglevel": "DEBUG", "file": "internal.log", "console": True},
            "core": {"loglevel": "DEBUG", "file": "core.log", "console": True},
            "network": {"loglevel": "DEBUG", "file": "network.log", "console": True},
            "dns": {"loglevel": "DEBUG", "file": "dns.log", "console": True},
        },
        "configs": ["config.json"],
        "misc": {
            "workers": 1,
            "ram-profile": "client",
            "mtu": 1500,
            "try-enabling-bbr": False,
        },
    }


def read_output(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def stop_process(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_case(binary, case_name, kind, settings, expected_error=None):
    with tempfile.TemporaryDirectory(prefix="waterwall-reality-config-") as temp_dir:
        run_dir = Path(temp_dir)
        (run_dir / "core.json").write_text(json.dumps(core_config()), encoding="utf-8")
        (run_dir / "config.json").write_text(json.dumps(make_config(kind, settings)), encoding="utf-8")
        output_path = run_dir / "output.log"

        with output_path.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                [str(binary)],
                cwd=run_dir,
                stdout=output,
                stderr=subprocess.STDOUT,
                text=True,
            )

        timeout = 30 if expected_error is None else 15
        deadline = time.monotonic() + timeout
        output = ""
        try:
            while time.monotonic() < deadline:
                output = read_output(output_path)
                if expected_error is None and STARTED_MARKER in output:
                    stop_process(process)
                    return
                if process.poll() is not None:
                    break
                time.sleep(0.02)

            output = read_output(output_path)
            if expected_error is None:
                require(
                    False,
                    f"{case_name}: valid configuration did not reach startup\n{output}",
                )
            require(process.poll() is not None, f"{case_name}: invalid configuration did not fail startup")
            require(
                expected_error in output,
                f"{case_name}: missing diagnostic {expected_error!r}\n{output}",
            )
        finally:
            stop_process(process)


def with_value(base, key, value):
    settings = copy.deepcopy(base)
    settings[key] = value
    return settings


def run_positive_cases(binary):
    client = {"sni": "tls.integration.test", "password": "p"}
    server = {"destination": "visitor", "password": "p"}
    tls = {"sni": "tls.integration.test"}

    cases = [
        ("client-defaults", "client", client),
        (
            "client-minimums-and-tls-options",
            "client",
            {
                **client,
                "salt": "s",
                "kdf-iterations": 1,
                "algorithm": "ChAcHa20-Poly1305",
                "verify": False,
                "x25519mlkem768": True,
                "verbose": False,
                "ech-sni-trick": "inner.example",
                "unknown-shared-setting": {"tolerated": True},
            },
        ),
        (
            "client-maximums-and-method",
            "client",
            {
                **client,
                "password": "p" * 32,
                "salt": "s" * 32,
                "kdf-iterations": 1000000,
                "method": "chacha20poly1305",
            },
        ),
        (
            "client-primary-wins",
            "client",
            {**client, "algorithm": "chacha20-poly1305", "method": {"ignored": True}},
        ),
        ("server-defaults", "server", server),
        (
            "server-minimums",
            "server",
            {
                **server,
                "salt": "s",
                "kdf-iterations": 1,
                "sniffing-attempts": 1,
                "algorithm": "ChAcHa20-Poly1305",
                "tls12-gcm-server-nonce-policy": "auto",
            },
        ),
        (
            "server-maximums-and-method",
            "server",
            {
                **server,
                "password": "p" * 32,
                "salt": "s" * 32,
                "kdf-iterations": 1000000,
                "sniffing-attempts": 1024,
                "method": "chacha20poly1305",
                "tls12-gcm-server-nonce-policy": "sequence",
            },
        ),
        (
            "server-sniffing-alias",
            "server",
            {**server, "sniffing-counter": 8, "tls12-gcm-server-nonce-policy": "counter"},
        ),
        (
            "server-primary-fields-win",
            "server",
            {
                **server,
                "algorithm": "chacha20-poly1305",
                "method": {"ignored": True},
                "sniffing-attempts": 8,
                "sniffing-counter": "ignored",
                "tls12-gcm-server-nonce-policy": "random",
            },
        ),
        ("tls-defaults", "tls", tls),
        (
            "tls-explicit-options",
            "tls",
            {
                **tls,
                "verify": False,
                "x25519mlkem768": True,
                "verbose": True,
                "ech-sni-trick": "inner.example",
            },
        ),
    ]

    for name, kind, settings in cases:
        run_case(binary, name, kind, settings)


def run_client_negative_cases(binary):
    base = {"sni": "tls.integration.test", "password": "p"}
    password_error = "RealityClient: 'password' must contain 1..32 bytes"
    salt_error = "RealityClient: 'salt' must contain 1..32 bytes"
    kdf_error = "RealityClient: 'kdf-iterations' must be an integer in range [1, 1000000]"

    cases = [
        ("client-empty-password", with_value(base, "password", ""), password_error),
        ("client-long-password", with_value(base, "password", "p" * 33), password_error),
        ("client-empty-salt", with_value(base, "salt", ""), salt_error),
        ("client-long-salt", with_value(base, "salt", "s" * 33), salt_error),
        (
            "client-malformed-primary-algorithm",
            {**base, "algorithm": 1, "method": "chacha20-poly1305"},
            "RealityClient: 'algorithm' must be a supported non-empty string",
        ),
        (
            "client-malformed-method",
            {**base, "method": False},
            "RealityClient: 'method' must be a supported non-empty string",
        ),
        (
            "client-unsupported-algorithm",
            {**base, "algorithm": "unknown"},
            "RealityClient: 'algorithm' is unsupported",
        ),
        ("client-kdf-fraction", with_value(base, "kdf-iterations", 1.5), kdf_error),
        ("client-kdf-zero", with_value(base, "kdf-iterations", 0), kdf_error),
        ("client-kdf-too-large", with_value(base, "kdf-iterations", 1000001), kdf_error),
        (
            "client-verify-type",
            with_value(base, "verify", 1),
            "TlsClient: 'verify' must be a boolean",
        ),
        (
            "client-x25519-type",
            with_value(base, "x25519mlkem768", "true"),
            "TlsClient: 'x25519mlkem768' must be a boolean",
        ),
        (
            "client-verbose-type",
            with_value(base, "verbose", None),
            "TlsClient: 'verbose' must be a boolean",
        ),
        (
            "client-ech-type",
            with_value(base, "ech-sni-trick", 1),
            "TlsClient: 'ech-sni-trick' must be a non-empty string",
        ),
        (
            "client-ech-empty",
            with_value(base, "ech-sni-trick", ""),
            "TlsClient: 'ech-sni-trick' must be a non-empty string",
        ),
    ]

    for type_name, value in [
        ("null", None),
        ("number", 1),
        ("boolean", True),
        ("array", []),
        ("object", {}),
    ]:
        cases.append((f"client-salt-{type_name}", with_value(base, "salt", value), salt_error))
    for type_name, value in [("string", "1"), ("null", None), ("boolean", True)]:
        cases.append((f"client-kdf-{type_name}", with_value(base, "kdf-iterations", value), kdf_error))

    for name, settings, error in cases:
        run_case(binary, name, "client", settings, error)


def run_server_negative_cases(binary):
    base = {"destination": "visitor", "password": "p"}
    password_error = "RealityServer: 'password' must contain 1..32 bytes"
    salt_error = "RealityServer: 'salt' must contain 1..32 bytes"
    kdf_error = "RealityServer: 'kdf-iterations' must be an integer in range [1, 1000000]"
    sniffing_error = "RealityServer: 'sniffing-attempts' must be an integer in range [1, 1024]"
    nonce_error = "RealityServer: 'tls12-gcm-server-nonce-policy' must be"

    cases = [
        ("server-empty-password", with_value(base, "password", ""), password_error),
        ("server-long-password", with_value(base, "password", "p" * 33), password_error),
        ("server-empty-salt", with_value(base, "salt", ""), salt_error),
        ("server-long-salt", with_value(base, "salt", "s" * 33), salt_error),
        (
            "server-malformed-primary-algorithm",
            {**base, "algorithm": None, "method": "chacha20-poly1305"},
            "RealityServer: 'algorithm' must be a supported non-empty string",
        ),
        (
            "server-malformed-method",
            {**base, "method": []},
            "RealityServer: 'method' must be a supported non-empty string",
        ),
        ("server-kdf-fraction", with_value(base, "kdf-iterations", 1.5), kdf_error),
        ("server-kdf-zero", with_value(base, "kdf-iterations", 0), kdf_error),
        ("server-kdf-too-large", with_value(base, "kdf-iterations", 1000001), kdf_error),
        ("server-sniffing-fraction", with_value(base, "sniffing-attempts", 1.5), sniffing_error),
        ("server-sniffing-zero", with_value(base, "sniffing-attempts", 0), sniffing_error),
        ("server-sniffing-too-large", with_value(base, "sniffing-attempts", 1025), sniffing_error),
        (
            "server-malformed-primary-sniffing",
            {**base, "sniffing-attempts": None, "sniffing-counter": 8},
            sniffing_error,
        ),
        (
            "server-malformed-sniffing-alias",
            {**base, "sniffing-counter": "8"},
            "RealityServer: 'sniffing-counter' must be an integer in range [1, 1024]",
        ),
        (
            "server-empty-nonce-policy",
            with_value(base, "tls12-gcm-server-nonce-policy", ""),
            nonce_error,
        ),
        (
            "server-unsupported-nonce-policy",
            with_value(base, "tls12-gcm-server-nonce-policy", "fixed"),
            nonce_error,
        ),
    ]

    for type_name, value in [
        ("null", None),
        ("number", 1),
        ("boolean", True),
        ("array", []),
        ("object", {}),
    ]:
        cases.append((f"server-salt-{type_name}", with_value(base, "salt", value), salt_error))
        cases.append(
            (
                f"server-nonce-policy-{type_name}",
                with_value(base, "tls12-gcm-server-nonce-policy", value),
                nonce_error,
            )
        )
    for type_name, value in [("string", "1"), ("null", None), ("boolean", True)]:
        cases.append((f"server-kdf-{type_name}", with_value(base, "kdf-iterations", value), kdf_error))
        cases.append(
            (f"server-sniffing-{type_name}", with_value(base, "sniffing-attempts", value), sniffing_error)
        )

    for name, settings, error in cases:
        run_case(binary, name, "server", settings, error)


def run_tls_negative_cases(binary):
    base = {"sni": "tls.integration.test"}
    cases = [
        ("tls-verify-type", "verify", 1, "TlsClient: 'verify' must be a boolean"),
        (
            "tls-x25519-type",
            "x25519mlkem768",
            None,
            "TlsClient: 'x25519mlkem768' must be a boolean",
        ),
        ("tls-verbose-type", "verbose", [], "TlsClient: 'verbose' must be a boolean"),
        (
            "tls-ech-type",
            "ech-sni-trick",
            False,
            "TlsClient: 'ech-sni-trick' must be a non-empty string",
        ),
        (
            "tls-ech-empty",
            "ech-sni-trick",
            "",
            "TlsClient: 'ech-sni-trick' must be a non-empty string",
        ),
    ]
    for name, key, value, error in cases:
        run_case(binary, name, "tls", with_value(base, key, value), error)


def main():
    require(len(sys.argv) == 2, "usage: reality_config_validation_test.py <Waterwall>")
    binary = Path(sys.argv[1]).resolve()
    require(binary.is_file(), f"Waterwall binary does not exist: {binary}")
    run_positive_cases(binary)
    run_client_negative_cases(binary)
    run_server_negative_cases(binary)
    run_tls_negative_cases(binary)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
