#!/usr/bin/env python3
"""Strict QUIC JSON and credential constructor coverage, without network peers.

Valid settings reach the real startup marker and orderly shutdown143. Invalid
types, fractional/range geometry, ALPN, carrier, DNS/A-label and PEM credentials
must exit nonzero with QUIC and the offending setting in the diagnostic.
Consumed setting names and the node envelope reject embedded-NUL aliases,
including duplicate fields and names/whole settings supplied through variables;
unrelated unknown settings retain their existing policy.
Canonical local certificate/key inputs are copied into each private directory.
CTest: waterwall.quic_config_startup_{client,server}, under the loopback
namespace wrapper. Each role owns an independent CTest budget; individual
startup and shutdown deadlines apply unchanged to every configuration.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config, STARTED_MARKER
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory


CERTIFICATES = Path(__file__).resolve().parent / "speedtests" / "_shared"


def run_case(binary, role, case, settings, error=None, *, variable_key=None,
             variable_field_name=None, invalid_utf8=False, node_field_alias=None,
             type_value_suffix="", variable_settings=False, duplicate_setting=None,
             duplicate_node_field=None):
    kind = "QuicClient" if role == "client" else "QuicServer"
    nodes = [
        {"name": "input", "type": "TcpListener", "next": "quic",
         "settings": {"address": "127.0.0.1", "port": 29846}},
        {"name": "quic", "type": kind, "next": "output", "settings": copy.deepcopy(settings)},
        {"name": "output", "type": "BlackHole", "settings": {"mode": "passive"}},
    ]
    nodes[1]["type"] += type_value_suffix
    if node_field_alias is not None:
        nodes[1][node_field_alias + "\0suffix"] = nodes[1].pop(node_field_alias)
    if duplicate_setting is not None:
        nodes[1]["settings"]["__QUIC_DUPLICATE_SETTING__"] = None
    if duplicate_node_field is not None:
        nodes[1]["__QUIC_DUPLICATE_NODE_FIELD__"] = None
    with RunDirectory("waterwall-quic-config-" + role + "-" + case + "-") as root:
        for name in ("server.crt", "server.key"):
            shutil.copyfile(CERTIFICATES / name, root / name)
        (root / "malformed.pem").write_text("not a PEM certificate or private key\n")
        (root / "core.json").write_text(json.dumps(core_config()))
        config = {"name": "quic-config", "nodes": nodes}
        if variable_key is not None:
            config["variables"] = {"quic_value": nodes[1]["settings"][variable_key]}
            nodes[1]["settings"][variable_key] = "__QUIC_VARIABLE_PLACEHOLDER__"
        if variable_field_name is not None:
            config.setdefault("variables", {})["quic_name"] = variable_field_name
            nodes[1]["settings"] = {
                "__QUIC_FIELD_NAME_PLACEHOLDER__" if key == variable_field_name else key: value
                for key, value in nodes[1]["settings"].items()
            }
        if variable_settings:
            config.setdefault("variables", {})["quic_settings"] = nodes[1]["settings"]
            nodes[1]["settings"] = "__QUIC_SETTINGS_PLACEHOLDER__"
        serialized = json.dumps(config)
        for marker, duplicate in (("__QUIC_DUPLICATE_SETTING__", duplicate_setting),
                                  ("__QUIC_DUPLICATE_NODE_FIELD__", duplicate_node_field)):
            if duplicate is not None:
                name, value = duplicate
                serialized = serialized.replace(json.dumps(marker) + ": null",
                                                json.dumps(name) + ": " + json.dumps(value))
        serialized = (serialized
                      .replace('"__QUIC_VARIABLE_PLACEHOLDER__"', '$quic_value$')
                      .replace('"__QUIC_FIELD_NAME_PLACEHOLDER__"', '$quic_name$')
                      .replace('"__QUIC_SETTINGS_PLACEHOLDER__"', '$quic_settings$').encode())
        if invalid_utf8:
            serialized = serialized.replace(b"__QUIC_INVALID_UTF8__", b"\xc0\xaf")
        (root / "config.json").write_bytes(serialized)
        output_path = root / "stdout.log"
        with Process([binary], cwd=root, log_path=output_path) as process:
            deadline = time.monotonic() + 8
            while process.poll() is None and time.monotonic() < deadline:
                output = output_path.read_text(errors="replace")
                if error is None and STARTED_MARKER in output:
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, case
                    return
                time.sleep(0.01)
            output = output_path.read_text(errors="replace")
            assert error is not None, f"{role}/{case}: valid configuration failed startup\n{output}"
            assert process.poll() is not None, f"{role}/{case}: invalid configuration did not fail startup"
            assert process.returncode != 0, f"{role}/{case}: invalid configuration returned success"
            assert "QUIC" in output.upper() and error in output, \
                f"{role}/{case}: missing QUIC/{error!r} diagnostic\n{output}"


def run(binary, roles=("client", "server")):
    for role in roles:
        base = ({"sni": "tls.integration.test"} if role == "client" else
                {"cert-file": "server.crt", "key-file": "server.key"})
        run_case(binary, role, "defaults", base)
        run_case(binary, role, "whole-settings-variable", base, variable_settings=True)
        for field in ("type", "settings"):
            run_case(binary, role, field + "-nul-envelope-key", base, field, node_field_alias=field)
        run_case(binary, role, "type-nul-envelope-value", base, "type", type_value_suffix="\0suffix")
        run_case(binary, role, "duplicate-type-alias", base, "type",
                 duplicate_node_field=("type\0suffix", "QuicClient" if role == "client" else "QuicServer"))
        run_case(binary, role, "duplicate-settings-alias", base, "settings",
                 duplicate_node_field=("settings\0suffix", {}))
        run_case(binary, role, "duplicate-settings-value", base, "protocol",
                 duplicate_node_field=("settings", {"protocol": "h3\0suffix"}))
        run_case(binary, role, "duplicate-setting-alias", {**base, "verbose": False}, "verbose",
                 duplicate_setting=("verbose\0suffix", True))
        run_case(binary, role, "duplicate-setting-value", {**base, "protocol": "h3"}, "protocol",
                 duplicate_setting=("protocol", "h3\0suffix"))
        run_case(binary, role, "whole-settings-variable-alias", {**base, "verbose\0suffix": True},
                 "verbose", variable_settings=True)
        run_case(binary, role, "whole-settings-variable-value", {**base, "protocol": "h3\0suffix"},
                 "protocol", variable_settings=True)
        run_case(binary, role, "custom-stream", {**base, "protocol": "waterwall-test",
            "carrier-mode": "stream", "handshake-timeout-ms": 1000, "idle-timeout-ms": 2000,
            "max-packet-size": 1200, "max-buffered-bytes": 65536,
            "receive-window-bytes": 16384, "max-buffered-buffers": 8, "verbose": True})
        run_case(binary, role, "maximum-geometry", {**base, "protocol": "x" * 255,
            "handshake-timeout-ms": 86400000, "idle-timeout-ms": 86400000,
            "max-packet-size": 1452, "max-buffered-bytes": 67108864,
            "receive-window-bytes": 16777216, "max-buffered-buffers": 65536})
        run_case(binary, role, "receive-window-maximum", {**base, "max-buffered-bytes": 67108864,
            "receive-window-bytes": 16777217}, "receive-window-bytes")
        invalid = {
            "protocol": [None, False, 3, [], {}, "", "x" * 256, "bad\nprotocol", "h3\x7f", "h\u00e9"],
            "carrier-mode": [None, True, 2, "", "auto", "tcp", "STREAM"],
            "handshake-timeout-ms": [False, "1000", 0, -1, 1.5, 86400001],
            "idle-timeout-ms": [True, [], 0, -1, 1.5, 86400001],
            "max-packet-size": [False, "1350", 1199, 1453, 65508, 1200.5],
            "max-buffered-bytes": [None, True, "2097152", 0, 67108865, 65536.5],
            "max-buffered-buffers": [False, "1024", 0, 65537, 8.5],
            "receive-window-bytes": [None, True, 0, 2097153, 16384.5],
            "verbose": [None, 0, "false", []],
        }
        if role == "client":
            invalid.update({"sni": [None, True, 10, "", "x" * 256, "a" * 64 + ".test",
                                    "-bad.test", "bad-.test", "bad..test", "bad.test.",
                                    "\u0645\u062b\u0627\u0644.test", "bad name.test"],
                            "verify": [None, 0, "false", []],
                            "ca-file": [True, 7, [], "missing.pem", "malformed.pem"]})
            run_case(binary, role, "replacement-trust", {**base, "ca-file": "server.crt"})
            run_case(binary, role, "verification-disabled", {**base, "verify": False})
        else:
            invalid.update({"cert-file": [None, True, 7, [], "missing.pem", "malformed.pem"],
                            "key-file": [None, False, 7, {}, "missing.pem", "malformed.pem"]})
        for key, values in invalid.items():
            for index, value in enumerate(values):
                settings = copy.deepcopy(base)
                settings[key] = value
                run_case(binary, role, f"{key}-{index}", settings, key)
        run_case(binary, role, "descriptor-geometry", {**base, "max-buffered-bytes": 65536,
            "max-buffered-buffers": 65536, "receive-window-bytes": 16384}, "max-buffered")
        # Lexical policy covers the full QUIC field set for both roles, even
        # when a setting is only semantically used by the opposite role.
        string_fields = {"protocol": "h3", "carrier-mode": "datagram", "sni": "tls.integration.test",
                         "ca-file": "server.crt", "cert-file": "server.crt", "key-file": "server.key"}
        for key, valid in string_fields.items():
            for variable in (False, True):
                run_case(binary, role, key + "-embedded-nul" + ("-variable" if variable else ""),
                         {**base, key: valid + "\0suffix"}, key, variable_key=key if variable else None)
                run_case(binary, role, key + "-invalid-utf8" + ("-variable" if variable else ""),
                         {**base, key: "__QUIC_INVALID_UTF8__"}, key,
                         variable_key=key if variable else None, invalid_utf8=True)
        setting_fields = {**string_fields, "handshake-timeout-ms": 1000, "idle-timeout-ms": 2000,
                          "max-packet-size": 1200, "max-buffered-bytes": 2097152,
                          "max-buffered-buffers": 8, "receive-window-bytes": 16384, "verbose": True,
                          "verify": False}
        for key, valid in setting_fields.items():
            aliased_key = key + "\0suffix"
            aliased = {name: value for name, value in base.items() if name != key}
            aliased[aliased_key] = valid
            for variable in (False, True):
                run_case(binary, role, key + "-nul-key-alias" + ("-variable" if variable else ""),
                         aliased, key, variable_field_name=aliased_key if variable else None)
        run_case(binary, role, "canonical-variable-key", {**base, "verbose": True},
                 variable_field_name="verbose")
        for variable in (False, True):
            run_case(binary, role, "unknown-setting" + ("-variable" if variable else ""),
                     {**base, "ignored\0suffix": "unrelated\0value"},
                     variable_field_name="ignored\0suffix" if variable else None)
        if role == "client":
            # A malformed alias must not disable default certificate verification
            # and hide an unreadable trust bundle. Require the key diagnostic,
            # rather than accepting an unrelated ca-file construction failure.
            for variable in (False, True):
                run_case(binary, role, "verify-alias-missing-ca" + ("-variable" if variable else ""),
                         {**base, "ca-file": "missing.pem", "verify\0suffix": False}, "verify",
                         variable_field_name="verify\0suffix" if variable else None)
            run_case(binary, role, "canonical-variable-verify", {**base, "verify": False},
                     variable_field_name="verify")
            run_case(binary, role, "missing-sni", {}, "sni")
        else:
            for key in ("cert-file", "key-file"):
                settings = {name: value for name, value in base.items() if name != key}
                run_case(binary, role, "missing-" + key, settings, key)
    print("QUIC constructor defaults, strict JSON, finite geometry and credential diagnostics passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("role", nargs="?", choices=("client", "server"))
    arguments = parser.parse_args()
    install_termination_handler()
    run(str(arguments.binary.resolve()), (arguments.role,) if arguments.role else ("client", "server"))
